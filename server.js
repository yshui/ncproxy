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

var app = connect()

var cfg = fs.readFileSync("config.json", 'utf8')
try {
	cfg = JSON.parse(cfg)
}catch(e){
	log.verbose("Failed to parse config.json")
	process.exit(1)
}

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
	if (!req.body.nouce)
		return res.end();
	if (cfg.password && cfg.password !== req.body.password)
		return res.end('{"err":"Password mismatch"}');
	var nouce = new Buffer(req.body.nouce, 'hex');
	var nouce2 = crypto.pseudoRandomBytes(8);
	var key = crypto.pseudoRandomBytes(32);
	var enc = new salsa(key, nouce);
	var dec = new salsa(key, nouce2);
	var rb = crypto.pseudoRandomBytes(16).toString('hex');
	var conn = {enc: enc,
		    dec: dec,
		    key: key,
		    id: rb,
		    conn: {}};
	connections[rb] = conn;

	res.end(JSON.stringify({
		id: rb,
		nouce: nouce2.toString('hex'),
		key: key.toString('hex')
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
	if (!connections[path])
		ws.close(1003);

	ws.on('close', function(){
		delete connections[path];
		if (ws.conn.master){
			var m = ws.conn.master;
			delete m.conn.conn[path];
		}
		clearInterval(ws.timer);
		if (ws.c)
			ws.c.destroy();
	});
	ws.timer = setInterval(function(){ws.ping(false);}, 10000);
	var errrep = function(repcode){
		var res = JSON.stringify({rep: repcode});
		res = new Buffer(res, 'utf8');
		mask(res, ws.conn.enc);
		ws.send(res, {binary: true});
		delete connections[path];
		if (ws.conn.master){
			var m = ws.conn.master;
			delete m.conn.conn[path];
		}
		ws.close(1003);
	};

	var handle_new_conn = function(j){
		if (!j.nouce || connections[j.id]) {
			log.error('Malformed client request');
			return ws.close(1003);
		}
		var nouce = new Buffer(j.nouce, 'hex');
		var nouce2 = crypto.pseudoRandomBytes(8);
		var enc = new salsa(ws.conn.key, nouce);
		var dec = new salsa(ws.conn.key, nouce2);
		var conn = {
			enc: enc,
			dec: dec,
			id: j.id,
			master: ws
		};
		connections[j.id] = conn;
		ws.conn.conn[j.id] = 1;

		log.verbose("nouce2: "+nouce2.toString('hex'));
		var res = JSON.stringify({
			cmd: "new_connection",
			id: j.id,
			nouce: nouce2.toString('hex'),
		});
		res = new Buffer(res, 'utf8');
		mask(res, ws.conn.enc);
		ws.send(res, {binary: true});
	}

	var handle_local_end = function(j){
		if (!connections[j.id]) {
			log.error('Malformed client request, nonexistent id');
			return ws.close(1003);
		}
		var conn = connections[j.id];
		if (!conn.master) {
			log.error('Malformed client request, local_end id point to a api websocket');
			return ws.close(1003);
		}
		if (!conn.master.conn.conn[j.id]){
			log.error('Malformed client request, local_end id point to socket doesnt belong to the client');
			return ws.close(1003);
		}
		if (!conn.c)
			return;
		conn.c.end();
	}

	var api_handler = function(data, opt){
		if (opt.binary !== true)
			return;
		mask(data, ws.conn.dec);
		var j;
		try{
			j = JSON.parse(data.toString('utf8'));
		}catch(e){
			log.error('Failed to parse client api request');
			log.info(data.toString('utf8'));
			ws.close(1003);
		}
		log.verbose(JSON.stringify(j));
		if (!j.id){
			log.error('Malformed client request');
			return ws.close(1003);
		}
		switch (j.cmd){
			case "new_connection":
				return handle_new_conn(j);
			case "local_end":
				return handle_local_end(j);
			default :
				log.error('Malformed client request');
				return ws.close(1003);
		}
	}

	var phase2 = function(data, opt){
		log.verbose(opt.binary);
		if (opt.binary !== true)
			return;
		mask(data, ws.conn.dec);
		ws.c.write(data);
	};

	var phase1 = function(data, opt){
		log.verbose(opt.binary);
		if (opt.binary !== true)
			return;
		//Decode data
		mask(data, ws.conn.dec);
		log.verbose(data.toString('utf8'));
		//json encoded target address
		var j = data.toString('utf8');
		try {
			j = JSON.parse(j);
		}catch(e){
			log.warn("Garbage from client");
			return ws.close(1003);
		}
		if (j.api === true) {
			ws.on('message', api_handler);
			return;
		}
		if (j.addrtype == 4)
			//Ipv6 not supported yet
			return errrep(8);
		//Open connection
		log.verbose(JSON.stringify(j));
		log.verbose("Target: "+j.addr+":"+j.port);
		ws.conn.c = ws.c = net.connect({host:j.addr, port:j.port, allowHalfOpen: true});
		ws.c.on('connect',function(){
			log.verbose("connected to "+j.addr+"("+ws.c.remoteAddress+"):"+j.port);
			var res = {rep: 0, atyp: 1,
				   addr: ws.c.localAddress,
				   port: ws.c.localPort};
			res = new Buffer(JSON.stringify(res), 'utf8');
			mask(res, ws.conn.enc);
			ws.send(res, {binary: true});
			ws.on("message", phase2);
		});
		ws.c.on('data', function(data){
			mask(data, ws.conn.enc);
			ws.send(data, {binary: true});
		});
		ws.c.on('error', function(e){
			log.error("Failed to connect to "+j.addr);
			log.error(e);
			if (e.code === 'ECONNREFUSED')
				return errrep(5);
			if (e.code === 'ENETUNREACH')
				return errrep(3);
			if (e.code === 'ENOTFOUND')
				return errrep(4);
			return errrep(1);
		});
		ws.c.on('end', function(){
			if (ws.conn.master) {
				//Send remote_end cmd
				var msg = JSON.stringify({cmd: "remote_end", id: ws.conn.id});
				msg = new Buffer(msg, 'utf8');
				mask(msg, ws.conn.enc);
				ws.send(msg, {binary: true});
			}
		});
		ws.c.on('close', function(){
			delete connections[path];
			if (ws.conn.master){
				var m = ws.conn.master;
				delete m.conn.conn[path];
			} else {
				log.warn("WTF?");
			}
			ws.close(1000);
		});
	};

	ws.conn = connections[path];
	ws.once("message", phase1);

	ws.on("close", function() {
		log.verbose("websocket connection close")
	})
})
