var server = require('websocket').server, 
	http = require('http');
var redis = require("redis"),
	client = redis.createClient();


var socket = new server({
    httpServer: http.createServer().listen(443),
	//Remove keepalive since the client will never need to send databack.
	//Could be renabled if i find a way to send the pong from the client.
    keepalive: false
});

client.subscribe("attack-map-production");
socket.on('request', function(request) {
    var connection = request.accept(null, request.origin);

    connection.on('message', function(message) {
	console.log(message);
		client.on("message", function(channel, message){
			//console.log(channel + ": " + message);
			//connection.sendUTF(channel + ": " + message);
			//connection.setHeader('Content-Type', 'application/json');
			connection.send(message);
		});
        //console.log(message.utf8Data);
        //connection.sendUTF('hello');
        //setTimeout(function() {
        //    connection.sendUTF('this is a websocket example');
        //}, 1000);
    });

    connection.on('close', function(connection) {
        console.log('connection closed');
    });
});
