var argyle = require('argyle');
//var scan = require('./scan');

var socks5_server = argyle(1084, '0.0.0.0', true);

socks5_server.on('connected', function(req, dest) {
    req.once('error', function(err) { dest.end(); req.end(); })
        .once('close', function() { dest.end(); req.end(); });
    dest.once('error', function(err) { dest.end(); req.end(); })
        .once('close', function() { dest.end(); req.end(); });

    req.on('data', function(chunk) {
        dest.write(chunk);
    });
    dest.on('data', function(chunk) {
        req.write(chunk);
    });
});
