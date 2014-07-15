var wsserver = require("ws").Server
var http = require("http")
var connect = require("connect")
var bp = require("body-parser")
var crypto = require("crypto")
var salsa = require("./salsa20.js")
var net = require("net")
var fs = require("fs")
var port = process.env.PORT || 5000
var util = require("util")

var app = connect()

var cfg = fs.readFileSync("config.json", 'utf8')
try {
	cfg = JSON.parse(cfg)
}catch(e){
	util.log("Failed to parse config.json")
	process.exit(1)
}

cfg.key = crypto.pbkdf2Sync(cfg.password, "", 1000, 256)

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
	util.log(req.body);
	if (!req.body.nouce)
		return res.end();
	var nouce = new Buffer(req.body.nouce, 'hex');
	var nouce2 = crypto.pseudoRandomBytes(8);
	var enc = new salsa(cfg.key, nouce);
	var dec = new salsa(cfg.key, nouce2);
	var rb = crypto.pseudoRandomBytes(16).toString('hex');
	var conn = {enc: enc,
		    dec: dec,
		    id: rb};
	connections[rb] = conn;

	util.log("nouce2: "+nouce2.toString('hex'));
	mask(nouce2, enc);
	res.setHeader('Content-Type', 'application/json');
	res.end(JSON.stringify({id: rb, nouce: nouce2.toString('hex')}))
})

var server = http.createServer(app)
server.listen(port)

util.log("http server listening on %d", port)

var wss = new wsserver({server: server})
util.log("websocket server created")

wss.on("connection", function(ws) {
	var path = ws.upgradeReq.url.slice(1);
	util.log("websocket, path:"+path)
	if (!connections[path])
		ws.close();

	var errrep = function(repcode){
		var res = JSON.stringify({rep: repcode});
		res = new Buffer(res, 'utf8');
		mask(res, ws.conn.enc);
		ws.send(res, {binary: true});
		connections[path] = undefined;
		ws.close();
	};

	var phase2 = function(data, opt){
		util.log(opt);
		if (opt.binary !== true)
			return;
		mask(data, ws.conn.dec);
		ws.c.write(data);
	};

	var phase1 = function(data, opt){
		util.log(opt);
		if (opt.binary !== true)
			return;
		//Decode data
		mask(data, ws.conn.dec);
		util.log(data);
		//json encoded target address
		var j = data.toString('utf8');
		try {
			j = JSON.parse(j);
		}catch(e){
			util.log("Garbage from client");
			return ws.close();
		}
		if (j.addrtype == 4)
			//Ipv6 not supported yet
			return errrep(8);
		//Open connection
		util.log(j);
		ws.c = net.connect({host:j.addr, port:j.port});
		ws.c.on('connect',function(){
			util.log("connected to "+j.addr+"("+ws.c.remoteAddress+"):"+j.port);
			var res = {rep: 0, atyp: 1,
				   addr: c.localAddress,
				   port: c.localPort};
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
			util.log("Failed to connect to "+j.addr);
			util.log(e);
			if (e.code === 'ECONNREFUSED')
				return errrep(5);
			if (e.code === 'ENETUNREACH')
				return errrep(3);
			if (e.code === 'ENOTFOUND')
				return errrep(4);
			return errrep(1);
		});
		ws.c.on('end', function(){
			connections[path] = undefined;
			ws.close();
		});
		ws.on('close', function(){
			connections[path] = undefined;
			if (ws.c)
				ws.c.end();
		});
	};

	ws.conn = connections[path];
	ws.once("message", phase1);

	ws.on("close", function() {
		util.log("websocket connection close")
	})
})
