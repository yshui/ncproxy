var ws = require("ws")
var http = require("http")
var crypto = require("crypto")
var salsa = require("./salsa20.js")
var net = require("net")
var fs = require("fs")
var cfg = fs.readFileSync("config.json", 'utf8')
try {
	cfg = JSON.parse(cfg)
}catch(e){
	console.log("Failed to parse config.json")
	process.exit(1)
}

cfg.key = crypto.pbkdf2Sync(cfg.password, "", 1000, 256)

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

var ssvr = net.createServer(function(c){
	c.on('end', function(){
		if (c.ws)
			c.ws.close();
	});
	c.on('error', function(err){
		console.log("Connection to server closed");
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
		console.log(data);
		var sres = new Buffer(2);
		sres[0] = 5;
		sres[1] = 0; //No auth
		var req =
			http.request({
				      host: cfg.host,
				      port: cfg.port,
				      headers: {"Content-Type": 'application/json'},
				      method: 'POST', path: '/'},
			function(res){
				console.log("Nouce response");
				var response = "";
				res.setEncoding('utf8');
				res.on('data', function(data){
					response += data;
				});
				res.on('end', function(){
					console.log("Nouce response end");
					console.log(response);
					try {
						response = JSON.parse(response);
						c.id = response.id;
						if (!c.id)
							throw "No id";
						if (!response.nouce)
							throw "No nouce";
						var nouce = new Buffer(response.nouce, 'hex');
						mask(nouce, c.dec);
						console.log("nouce2: "+nouce.toString('hex'));
						c.enc = new salsa(cfg.key, nouce);
					}catch(e){
						console.log("Can't parse server response");
						console.log(e);
						c.end();
						return;
					}
					c.once('data', phase2);
					c.write(sres);
				});
			});
		req.on('error', function(err){
			console.log(err);
			errrep(1);
		});
		var rb = crypto.pseudoRandomBytes(8);
		var opt = JSON.stringify({
			nouce: rb.toString('hex')
		});
		c.dec = new salsa(cfg.key, rb);
		req.write(opt);
		req.end();
	};
	c.once('data', phase1);
	var phase2 = function(data){
		console.log("Received socks5 request");
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
		var url = "ws://"+cfg.host;
		if (cfg.port)
			url += ":"+cfg.port;
		url += "/"+c.id;
		console.log("creating websocket to "+url);
		c.ws = new ws(url, {mask: false});
		j = JSON.stringify(j);
		j = new Buffer(j, 'utf8');
		mask(j, c.enc);
		c.ws.on('error', function(err){
			console.log('Websocket error');
		});
		c.ws.on('close', function(err){
			console.log('Websocket closed');
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
			console.log(j);
			try {
				j = JSON.parse(j);
			}catch(e){
				console.log("Can't parse websocket message");
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
ssvr.listen(cfg.localport);
