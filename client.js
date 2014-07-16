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
var connections = {};
try {
	cfg = JSON.parse(cfg)
}catch(e){
	log.verbose("Failed to parse config.json")
	process.exit(1)
}

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
var master, menc, mdec, mkey;
var svr_url = "ws://"+cfg.host;
if (cfg.port)
	svr_url += ":"+cfg.port;
var rb = crypto.pseudoRandomBytes(8);
var opt = {nouce: rb.toString('hex')};
if (cfg.password)
	opt.password = cfg.password;
var handle_master_cmd = function(j, opt){
	if (!opt.binary)
		return;
	mask(j, mdec);
	j = j.toString('utf8');
	log.verbose(j);
	try {
		j = JSON.parse(j);
	}catch(e){
		log.error("Garbage from server, abort.");
		log.error(JSON.stringify(e));
		process.exit(1);
	}
	var conn, res;
	switch(j.cmd){
		case "new_connection":
			conn = connections[j.id];
			if (!conn || !j.nouce) {
				log.error("Garbage from server, abort.");
				process.exit(1);
			}
			var nouce = new Buffer(j.nouce, 'hex');
			conn.c.enc = new salsa(mkey, nouce);
			conn.c.once('data', conn.phase2);
			delete conn.phase2;
			res = new Buffer(2);
			res[0] = 5;
			res[1] = 0;
			conn.c.write(res);
			break;
		case "remote_end":
			conn = connections[j.id];
			if (!conn) {
				log.error("Garbage from server, abort.");
				process.exit(1);
			}
			conn.c.end();
			break;
		default :
			log.error("Garbage from server, abort. unknown cmd.");
			process.exit(1);
	}
};
log.verbose("Starting https connection to server");
var req = https.request({
	host: cfg.host, port: cfg.api_port,
	headers: {"Content-Type": 'application/json'},
	method: 'POST', path: '/'
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
			mkey = new Buffer(response.key, 'hex');
			var nouce = new Buffer(response.nouce, 'hex');
			menc = new salsa(mkey, nouce);
			mdec = new salsa(mkey, rb);
		}catch(e){
			log.verbose("Can't parse server response");
			log.verbose(e);
			process.exit(1);
		}
		master = new ws(svr_url+"/"+response.id, {mask: false});
		master.on('open', function(){
			esend(master, JSON.stringify({api: true}), menc);
			ssvr.listen(cfg.localport);
		});
		master.on('message', handle_master_cmd);
		master.on('close', function(){
			log.error("Master connection gone");
			process.exit(1);
		});
		master.on('error', function(err){
			log.error("master error");
			log.error(JSON.stringify(err));
		});
		master.on('ping', function(){
			log.verbose("ws ping from server (master connection)");
			master.pong(false);
		});
	});
});
req.on('error', function(err){
	log.error(err);
	process.exit(1);
});
req.write(JSON.stringify(opt));
req.end();

ssvr = net.createServer(function(c){
	c.on('end', function(){
		//send local_end
		var req = {
			cmd: "local_end",
			id: c.id
		}
		esend(master, JSON.stringify(req), menc);
	});
	c.on('close', function(){
		if (c.ws)
			c.ws.close();
	});
	c.on('error', function(err){
		log.error("Socks5 connection closed");
		log.error(JSON.stringify(err));
	});
	var errrep = function (repcode){
		var res = new Buffer(10);
		res[0] = 5;
		res[1] = repcode & 0xff;
		res[2] = 0;
		res[3] = 1;
		res[4] = res[5] = res[6] = res[7] = 0;
		res[8] = res[9] = 0;
		c.write(res);
		c.end();
	}
	var phase1 = function(data){
		//Phase1: Hello from clients
		if (data[0] != 5)
			//Not socks5
			return c.end();
		log.verbose(data);
		var n1 = crypto.pseudoRandomBytes(8);
		var conn = {
			id: crypto.pseudoRandomBytes(16).toString('hex'),
			c: c,
			phase2: phase2
		};
		var req = {
			cmd: "new_connection",
			id: conn.id,
			nouce: n1.toString('hex')
		};
		c.id = conn.id;
		c.dec = new salsa(mkey, n1);
		connections[conn.id] = conn;
		esend(master, JSON.stringify(req), menc);
	};
	c.once('data', phase1);
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
			j.port = data.readInt16BE(8);
			break;
		case 3:
			var len = data[4];
			var tmp = data.slice(5, 5+len);
			j.addr = tmp.toString('utf8');
			j.port = data.readInt16BE(5+len);
			break;
		}
		log.info("socks5 target: "+j.addr+":"+j.port);
		var url = svr_url+"/"+c.id;
		log.verbose("creating websocket to "+url);
		c.ws = new ws(url, {mask: false});
		j = JSON.stringify(j);
		j = new Buffer(j, 'utf8');
		mask(j, c.enc);
		c.ws.on('error', function(err){
			log.error('Websocket error');
			log.error(JSON.stringify(err));
		});
		c.ws.on('close', function(err){
			log.verbose('Websocket closed');
			c.destroy();
		});
		c.ws.once("message", function ws_phase1(data, opt){
			if (opt.binary !== true){
				c.ws.close();
				c.end();
				return;
			}
			mask(data, c.dec);
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
			c.ws.on('message', ws_phase2);
			c.write(res);
		});
		c.ws.on('open', function(){
			c.ws.send(j, {binary: true});
		});
		c.ws.on('ping', function(){
			log.verbose("ws ping from server (data connection)");
			c.ws.pong(false);
		});
	};
	var phase3 = function(data){
		mask(data, c.enc);
		c.ws.send(data, {binary: true});
	};
	var ws_phase2 = function(data, opt){
		if (opt.binary !== true)
			return;
		mask(data, c.dec);
		c.write(data);
	}
});
