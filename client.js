var ws = require("ws")
var https = require("https")
var crypto = require("crypto")
var salsa = require("./salsa20.js")
var net = require("net")
var fs = require("fs")
var log = require("npmlog")
log.level = "verbose";
var cfg = fs.readFileSync("config.json", 'utf8')
var ssvr;
try {
	cfg = JSON.parse(cfg)
}catch(e){
	log.error("Failed to parse config.json")
	process.exit(1)
}

if (cfg.log_level)
	log.level = cfg.log_level;

function mask(data, gen){
	if (!(data instanceof Buffer))
		return
	if (!(gen instanceof salsa))
		return
	var out = gen.getBytes(data.length);
	var i = 0;
	for (i = 0; i < data.length; i++)
		data[i] ^= out[i];
}

function esend(ws, str, gen){
	var b = new Buffer(str, 'utf8');
	mask(b, gen);
	ws.send(b, {binary: true});
}

//Request a master websocket
var master, menc, mcount = 0, mid;
var svr_url = "ws://"+cfg.host;
if (cfg.port)
	svr_url += ":"+cfg.port;
var rb = crypto.pseudoRandomBytes(8);
if (cfg.password)
	opt.password = cfg.password;
log.verbose("Starting https connection to server");
var req = https.request({
	host: cfg.host, port: cfg.api_port,
	headers: {"Content-Type": 'application/json'},
	method: 'POST', path: '/', secureProtocol: 'SSLv3_method'
},function(res){
	log.verbose("master nouce response");
	var response = "";
	res.setEncoding('utf8');
	res.on('data', function(data){
		response += data;
	});
	res.on('error', function(err){
		log.error("Read server response error");
		log.error(JSON.stringify(err));
		process.exit(1);
	});
	res.on('end', function(){
		log.verbose("master nouce response end");
		log.verbose(response);
		try {
			response = JSON.parse(response);
			if (!response.id)
				throw "No id";
			if (!response.nouce)
				throw "No nouce";
			if (!response.key)
				throw "No key";
			var nouce = new Buffer(response.nouce, 'base64');
			var key = new Buffer(response.key, 'base64');
			mid = response.id;
			menc = new salsa(key, nouce);
		}catch(e){
			log.verbose("Can't parse server response");
			log.verbose(e);
			process.exit(1);
		}
	});
});
req.on('error', function(err){
	log.error(err);
	process.exit(1);
});
req.end();

ssvr = net.createServer({allowHalfOpen: true}, function(c){
	c.on('end', function(){
		//send local_end
		log.verbose("socks5 local end, "+c.targetAddr);
		c.localEnded = true;
		if (c.ws) {
			var b = new Buffer('local_end', 'utf8');
			mask(b, c.ws.enc);
			c.ws.ping(b, {binary: true}, false);
		}
	});
	c.on('close', function(){
		if (c.ws)
			c.ws.close();
		if (c.id)
			delete connections[c.id];
	});
	c.on('error', function(err){
		log.error("Socks5 connection closed");
		log.error(JSON.stringify(err));
	});
	var errrep = function (repcode){
		if (c.closed)
			return;
		if (c.connected)
			return c.destroy();
		c.closed = true;
		var res = new Buffer(10);
		res[0] = 5;
		res[1] = repcode & 0xff;
		res[2] = 0;
		res[3] = 1;
		res[4] = res[5] = res[6] = res[7] = 0;
		res[8] = res[9] = 0;
		c.write(res);
		c.end();
	};
	var ws_forward = function(data, opt){
		if (c.remoteEnded) {
			log.warn("msg from server after remote_end");
			return;
		}
		if (opt.binary !== true)
			return;
		mask(data, c.dec);
		c.write(data);
	}
	var phase3 = function(data){
		mask(data, c.enc);
		c.ws.send(data, {binary: true});
	};
	var phase2 = function(data){
		log.verbose("Received socks5 request");
		if (data[0] != 5)
			return c.end();
		if (data[1] != 1)
			return errrep(7);
		if (data[3] == 4)
			return errrep(8);
		var j = {addrtype: data[3], addr: "", port: 0};
		switch(data[3]){
		case 1:
			//4 bytes ip
			var tmp = data.slice(4, 8);
			j.addr = tmp[0]+"."+tmp[1]+"."+tmp[2]+"."+tmp[3];
			j.port = data.readUInt16BE(8);
			break;
		case 3:
			var len = data[4];
			var tmp = data.slice(5, 5+len);
			j.addr = tmp.toString('utf8');
			j.port = data.readUInt16BE(5+len);
			break;
		}
		log.info("socks5 target: "+j.addr+":"+j.port);
		c.targetAddr = j.addr;
		j = JSON.stringify(j);
		j = new Buffer(j, 'utf8');
		c.ws.once('message', function(data, opt){
			if (opt.binary !== true)
				return;
			mask(data, c.ws.dec);
			var j = data.toString('utf8');
			log.verbose(j);
			try {
				j = JSON.parse(j);
			}catch(e){
				log.error("Can't parse websocket message");
				c.ws.close();
				c.end();
				return;
			}
			if (j.rep !== 0){
				if (!j.rep)
					j.rep = 1;
				errrep(j.rep);
				c.ws.close();
				return;
			}
			if (j.atyp !== 1){
				errrep(1);
				c.ws.close();
				return;
			}
			var frag = j.addr.split('.');
			var i;
			var res = new Buffer(10);
			res.write('05000001', 0, 4, 'hex');
			for(i = 0; i < 4; i++) {
				var p = parseInt(frag[i]);
				if (isNaN(p)){
					errrep(1);
					c.ws.close();
					return;
				}
				res[4+i] = p & 0xff;
			}
			res.writeUInt16BE(j.port, 8);
			c.on('data', phase3);
			c.ws.on('message', ws_forward);
			c.write(res);
		});
		c.ws.on('ping', function(msg){
			log.silly("ping from server");
			c.ws.pong(msg, {binry: true}, false);
			mask(msg, c.ws.dec);
			if (msg === 'remote_end') {
				c.end();
				c.remoteEnded = true;
			}else if(msg !== 'nop') {
				log.warn("malformed ping from server");
				c.ws.close(1003);
				c.destroy();
			}
		});
		c.ws.send(j, {binary: true});
	};
	var phase1 = function(data){
		//Phase1: Hello from clients
		if (data[0] != 5)
			//Not socks5
			return c.end();
		var res = new Buffer('0501', 'hex');
		var url = svr_url+"/"+mid+'-'+mcount;
		log.verbose("creating websocket to "+url);
		c.ws = new ws(url, {mask: false});
		c.ws.on('open', function(){
			var data = crypto.pseudoRandomBytes(40);
			var key = data.slice(0, 32);
			var nouce = data.slice(32, 40);
			c.ws.dec = new salsa(key, nouce);
			c.ws.key = key;
			mask(data, menc);
			c.ws.send(data, {binary: true});
		});
		c.ws.once('message', function(msg){
			if (msg.length != 8){
				log.warn("Malformed nouce");
				ws.close();
				return errrep(1);
			}
			mask(msg, c.ws.dec);
			c.ws.enc = new salsa(c.ws.key, msg);
			delete c.ws.key;
			c.write(res);
			c.once('data', phase2);
		});
		c.ws.on('error', function(){
			log.error('Websocket error');
			log.error(JSON.stringify(err));
		});
		c.ws.on('close', function(){
			errrep(1);
		});
	};
	c.once('data', phase1);
});
