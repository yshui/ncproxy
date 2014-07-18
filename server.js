var wsserver = require("ws").Server
var http = require("http")
var connect = require("connect")
var bp = require("body-parser")
var crypto = require("crypto")
var salsa = require("./salsa20.js")
var net = require("net")
var fs = require("fs")
var log = require("npmlog")
log.stream = process.stdout
log.level = 'verbose';
var port = process.env.PORT || 5000
var util = require("util")
//Master cipher pairs
var cps = {};

var app = connect()

var cfg = fs.readFileSync("config.json", 'utf8')
try {
	cfg = JSON.parse(cfg)
}catch(e){
	log.verbose("Failed to parse config.json")
	process.exit(1)
}

if (cfg.log_level)
	log.level = cfg.log_level;

var connections = {};

function mask(data, gen){
	if (!(data instanceof Buffer))
		throw "Data is not buffer";
	if (!(gen instanceof salsa))
		throw "Gen is not a salsa20 cipher";
	var out = gen.getBytes(data.length);
	var i = 0;
	for (i = 0; i < data.length; i++)
		data[i] ^= out[i];
}

app.use(bp.json());
app.use(function(req, res){
	log.verbose(JSON.stringify(req.body));
	res.setHeader('Content-Type', 'application/json');
	if (cfg.password && cfg.password !== req.body.password)
		return res.end('{"err":"Password mismatch"}');
	var nouce = crypto.pseudoRandomBytes(8);
	var key = crypto.pseudoRandomBytes(32);
	var dec = new salsa(key, nouce);
	var rb;
	do {
		rb = crypto.pseudoRandomBytes(16).toString('hex');
	}while(cps[rb]);
	var cp = {dec: dec,
		  id: rb};
	cps[rb] = cp;

	res.end(JSON.stringify({
		id: rb,
		nouce: nouce.toString('base64'),
		key: key.toString('base64')
	}))
})

var server = http.createServer(app)
server.listen(port)

log.verbose("http server listening on %d", port)

var wss = new wsserver({server: server})
log.verbose("websocket server created")

wss.on("connection", function(ws) {
	var path = ws.upgradeReq.url.slice(1);
	log.verbose("websocket, path:"+path)
	var pathp = path.split('-');
	if (!cps[pathp[0]])
		ws.close(1003);
	ws.cp = cps[pathp[0]];
	ws.id = pathp[1];

	ws.on('close', function(){
		clearTimeout(ws.timer);
		if (ws.c)
			ws.c.destroy();
	});
	var keepalive = function(){
		var b = new Buffer('nop', 'utf8');
		mask(b, ws.enc);
		ws.ping(b, {binary: true}, false);
		ws.timer = setTimeout(keepalive, 10000);
	}
	var errrep = function(repcode){
		var res = JSON.stringify({rep: repcode});
		res = new Buffer(res, 'utf8');
		mask(res, ws.enc);
		ws.send(res, {binary: true});
		ws.close(1003);
	};

	var phase2 = function(data, opt){
		log.verbose(opt.binary);
		if (opt.binary !== true)
			return;
		if (ws.localEnded) {
			log.warn("Received data from websocket after local_end");
			return;
		}
		mask(data, ws.dec);
		ws.c.write(data);
	};

	var phase1 = function(data, opt){
		if (opt.binary !== true)
			return;
		//Decode data
		mask(data, ws.dec);
		//json encoded target address
		var j = data.toString('utf8');
		log.verbose(j);
		try {
			j = JSON.parse(j);
		}catch(e){
			log.warn("Garbage from client");
			return ws.close(1003);
		}
		if (j.addrtype == 4)
			//Ipv6 not supported yet
			return errrep(8);
		//Open connection
		log.verbose("Target: "+j.addr+":"+j.port);
		ws.c = net.connect({host:j.addr, port:j.port, allowHalfOpen: true});
		ws.c.connected = false;
		ws.c.on('connect',function(){
			ws.c.connected = true;
			log.verbose("connected to "+j.addr+"("+ws.c.remoteAddress+"):"+j.port);
			var res = {rep: 0, atyp: 1,
				   addr: ws.c.localAddress,
				   port: ws.c.localPort};
			res = new Buffer(JSON.stringify(res), 'utf8');
			mask(res, ws.enc);
			ws.send(res, {binary: true});
			ws.on("message", phase2);
			ws.on('ping', function(msg, opt){
				if (opt.binary !== true)
					return;
				ws.pong(msg, {binary: true});
				mask(msg, ws.dec);
				msg = msg.toString('utf8');
				if (msg == "local_end") {
					ws.c.end();
					ws.localEnded = true;
				} else if(msg != "nop") {
					log.warn("malformed ping from client"+msg);
					ws.close(1003);
					ws.c.destroy();
				}
			});
		});
		ws.c.on('data', function(data){
			mask(data, ws.enc);
			ws.send(data, {binary: true});
		});
		ws.c.on('error', function(e){
			if (!ws.c.connected) {
				log.error("Failed to connect to "+j.addr);
				log.error(JSON.stringify(e));
				if (e.code === 'ECONNREFUSED')
					return errrep(5);
				if (e.code === 'ENETUNREACH')
					return errrep(3);
				if (e.code === 'ENOTFOUND')
					return errrep(4);
				return errrep(1);
			}else{
				log.error("Connection to remote server closed with error");
				log.error(JSON.stringify(e));
			}
		});
		ws.c.on('end', function(){
			log.verbose("remote end ended");
			//Send remote_end cmd
			var msg = "remote_end";
			msg = new Buffer(msg, 'utf8');
			mask(msg, ws.enc);
			ws.ping(msg, {binary: true}, false);
		});
		ws.c.on('close', function(){
			ws.close(1000);
		});
	};

	var phase0 = function(data, opt){
		//key exchange phase
		if (opt.binary !== true)
			return;
		log.verbose("Key exchange message from client");
		mask(data, ws.cp.dec);
		if (data.length != 40){
			log.warn("Malformed key");
			return ws.close(1003);
		}
		var key = data.slice(0, 32);
		var nouce = data.slice(32, 40);
		log.verbose("key: "+key.toString('base64'));
		log.verbose("nouce(client): "+nouce.toString('base64'));
		ws.enc = new salsa(key, nouce);
		nouce = crypto.pseudoRandomBytes(8);
		log.verbose("nouce(server): "+nouce.toString('base64'));
		ws.dec = new salsa(key, nouce);
		mask(nouce, ws.enc);
		ws.send(nouce, {binary: true});
		ws.once('message', phase1);
		ws.timer = setTimeout(keepalive, 10000);
	}

	ws.once("message", phase0);

	ws.on("close", function() {
		log.verbose("websocket connection close, master id="+ws.cp.id+" ,id="+ws.id)
	})
})
