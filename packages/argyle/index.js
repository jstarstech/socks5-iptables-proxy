/*jshint laxcomma:true asi:true */
var net = require('net')
  , util = require('util')
  , EventEmitter = require('events').EventEmitter

/////// TELNET
var telnet = require('telnet-client'),
    async = require("async");

var connection = new telnet();

params = process.argv.slice(2)

if (params.length) {
    params = JSON.parse(new Buffer(params, 'base64').toString('utf8'));
} else {
    params = {
      host: '5.35.33.51',
      port: 23,
      shellPrompt: /(#)s.*$/g,
      loginPrompt: /login[: ]*$/i,
      username: 'admin',
      password: '89652773088',
    };
}

var telnet_ready = false;

connection.on('ready', function(prompt) {
    console.log("-- Telnet connected --");

    queue.push(['iptables -D INPUT -p tcp --destination-port 9000:20000 -j ACCEPT; iptables -D FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT; iptables -t nat -D PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS; iptables -t nat -F FORWARDS; iptables -t nat -X FORWARDS; iptables -D INPUT -j DROP; iptables -D INPUT -m state --state INVALID -j DROP; iptables -D FORWARD -m state --state INVALID -j DROP; iptables -D FORWARD ! -i br0 -o eth2.2 -j DROP; iptables -D FORWARD -j DROP; iptables -D FORWARD -i ! br0 -o eth0 -j DROP; iptables -D FORWARD -i ! br0 -o ppp0 -j DROP'], function(response) {
        console.log("-- Firewall FLUSH --");
    });

    queue.push(['iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && iptables -t nat -N FORWARDS && iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'], function(response) {
        console.log("-- Firewall ACCEPT --");
        
        telnet_ready = true;
    });

}).connect(params);

connection.on('timeout', function() {
  console.log('socket timeout!')
  //connection.end();
});

connection.on('close', function() {
  console.log('connection closed');
});
/////// TELNET

/////// QUEUE
var tasks = [];

function run_command(cmd, callback) {
    tasks.push(cmd);
    callback('');
}

var queue = async.queue(run_command, 1);

queue.drain = function() {
    queue.pause();

    var cmds = tasks.join('; ');

    connection.exec(cmds, function(response) {
        queue.resume();

        tasks = [];

        console.log("-- All tasks are complete --");
    });
};

queue.concurrency = 10;
/////// QUEUE

var domains_map = [];
for (var i = 0; i < 9000; i++) domains_map[i] = 1;

var debugOut = console.log.bind(console)

module.exports = function(port, host, debug) {
  if(!port) port = 8080
  if(!host) host = '127.0.0.1'

  return new Argyle(port, host, debug)
}

function Argyle(port, host, debug) {
  Argyle.super_.call(this)
  var self = this

  if(!!debug) this._debug = debugOut
  else this._debug = function() {}

  this.serverSock = net.createServer()
  this.serverSock.on('listening', function() {
    var addr = self.serverSock.address()
    self._debug('socks server listening on %s:%s', addr.address, addr.port)
  }).on('connection', function(client) {
    self.handleConnection(client)
  })

  this.serverSock.listen(port, host)
}
util.inherits(Argyle, EventEmitter);

Argyle.socksVersion = 5

var STATES =  { handshake: 0
              , request: 1
              , forwarding: 2
              }
Argyle.prototype.handleConnection = function(client) {
  var curState = STATES.handshake
    , handlers = {}
    , self = this

  function onClientData(chunk) {
    handlers[curState](chunk)
  }

  client.on('end', function() {
  }).on('error', function(err) {
  }).on('data', onClientData)

  var buffer = null
  handlers[STATES.handshake] = function(chunk) {
    buffer = expandAndCopy(buffer, chunk)
    if(buffer.length < 2) return

    var socksVersion = buffer[0]
    if(socksVersion != Argyle.socksVersion) {
      self._debug('unsupported client version: %d', socksVersion)
      return client.end()
    }

    var nMethods = buffer[1];
    if(buffer.length < nMethods + 2) return;
    for(var i = 0; i < nMethods; i++) {
      // try to find the no-auth method type, and if found, choose it
      if(buffer[i+2] === 0) {
        client.write(new Buffer([0x05, 0x00]))
        curState++
        if(buffer.length > nMethods + 2) {
          var newChunk = buffer.slice(nMethods + 2)
          buffer = null
          handlers[STATES.request](newChunk)
        }
        buffer = null
        return
      }
    }

    self._debug('No supported auth methods found, disconnecting.')
    client.end(new Buffer([0x05, 0xff]))
  }

  var proxyBuffers = []
  handlers[STATES.request] = function(chunk) {
    buffer = expandAndCopy(buffer, chunk)
    if(buffer.length < 4) return

    var socksVersion = buffer[0];
    if(socksVersion != Argyle.socksVersion) {
      self._debug('unsupported client version: %d', socksVersion)
      return client.end()
    }

    var cmd = buffer[1];
    if(cmd != 0x01) {
      self._debug('unsupported command: %d', cmd)
      return client.end(new Buffer([0x05, 0x01]))
    }

    var addressType = buffer[3]
      , host
      , port
      , responseBuf
    if(addressType == 0x01) { // ipv4
      if(buffer.length < 10) return // 4 for host + 2 for port
      host = util.format('%d.%d.%d.%d', buffer[4], buffer[5], buffer[6], buffer[7])
      port = buffer.readUInt16BE(8)
      responseBuf = new Buffer(10)
      buffer.copy(responseBuf, 0, 0, 10)
      buffer = buffer.slice(10)
    }
    else if(addressType == 0x03) { // dns
      if(buffer.length < 5) return // if no length present yet
      var addrLength = buffer[4]
      if(buffer.length < 5 + addrLength + 2) return // host + port
      host = buffer.toString('utf8', 5, 5+addrLength)
      port = buffer.readUInt16BE(5+addrLength)
      responseBuf = new Buffer(5 + addrLength + 2)
      buffer.copy(responseBuf, 0, 0, 5 + addrLength + 2)
      buffer = buffer.slice(5 + addrLength + 2)
    }
    else if(addressType == 0x04) { // ipv6
      if(buffer.length < 22) return // 16 for host + 2 for port
      host = buffer.slice(4, 20)
      port = buffer.readUInt16BE(20)
      responseBuf = new Buffer(22)
      buffer.copy(responseBuf, 0, 0, 22)
      buffer = buffer.slice(22);
    }
    else {
      self._debug('unsupported address type: %d', addressType)
      return client.end(new Buffer([0x05, 0x01]))
    }

    self._debug('Request to %s:%s', host, port)
    curState++

    var connected = false
    client.pause()
    var dest_host = host + ':' + port;

    if ( ! telnet_ready) {
        return client.end(new Buffer([0x05, 0x01]))
    }

    if (domains_map.indexOf(dest_host) >= 0) {
        var req_port = domains_map.indexOf(dest_host);

        console.log("Found (" + req_port + "): " + params.host + ':' + req_port + ' = ' + dest_host);

        var dest = net.createConnection(req_port, params.host, function() {
        //var dest = net.createConnection(port, host, function() {
          responseBuf[1] = 0
          responseBuf[2] = 0
          client.write(responseBuf) // emit success to client
          client.removeListener('data', onClientData)

          client.resume()

          self.emit('connected', client, dest)
          connected = true
          if(buffer && buffer.length) {
            client.emit(buffer)
            buffer = null
          }
          for(var j = 0; j < proxyBuffers.length; j++) { // re-emit any leftover data for proxy to handle
            client.emit('data', proxyBuffers[i])
          }
          proxyBuffers = []
        }).once('error', function(err) {
          if(!connected) {
            client.end(new Buffer([0x05, 0x01]))
          }
        }).once('close', function() {
          if(!connected) {
            client.end()
          }
        }).once('timeout', function() {
          if(!connected) {
            client.end()
          }
        })
    } else {
        domains_map.push(dest_host);
        var req_port = domains_map.indexOf(dest_host);

        queue.push(['iptables -t nat -I FORWARDS -p TCP --dport '+ req_port +' -j DNAT --to "'+ host +'":' + port + '; iptables -t nat -D POSTROUTING -d "' + host +'" -p TCP --dport ' + port + ' -j MASQUERADE; iptables -t nat -I POSTROUTING -d "' + host +'" -p TCP --dport ' + port + ' -j MASQUERADE'], function(response) {
            console.log("Added (" + req_port + "): " + params.host + ':' + req_port + ' = ' + dest_host);
            var dest = net.createConnection(req_port, params.host, function() {
              responseBuf[1] = 0
              responseBuf[2] = 0

              client.write(responseBuf) // emit success to client
              client.removeListener('data', onClientData)
              client.resume()
              self.emit('connected', client, dest)
              connected = true
              if(buffer && buffer.length) {
                client.emit(buffer)
                buffer = null
              }
              for(var j = 0; j < proxyBuffers.length; j++) { // re-emit any leftover data for proxy to handle
                client.emit('data', proxyBuffers[i])
              }
              proxyBuffers = []
            }).once('error', function(err) {
              if(!connected) {
                client.end(new Buffer([0x05, 0x01]))
              }
            }).once('close', function() {
              if(!connected) {
                client.end()
              }
            }).once('timeout', function() {
              if(!connected) {
                client.end()
              }
            })
        });
    }
  }

  handlers[STATES.forwarding] = function (chunk) {
    proxyBuffers.push(chunk);
  }
}

function expandAndCopy(old, newer) {
  if(!old) return newer;
  var newBuf = new Buffer(old.length + newer.length);
  old.copy(newBuf);
  newer.copy(newBuf, old.length);

  return newBuf;
}

// vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab

