import net from 'net';
import util from 'util';
import {EventEmitter} from 'events';
import {Telnet} from 'telnet-client';
import async from "async";

let params = process.argv.slice(2)

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
        timeout: 1500
    };
}

const queue = async.queue(run_command, 1);

/////// TELNET
let telnet_ready = false;
const connection = new Telnet();
connection.on('ready', prompt => {
    console.log("-- Telnet connected --");

    queue.push(['iptables -D INPUT -p tcp --destination-port 9000:20000 -j ACCEPT; iptables -D FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT; iptables -t nat -D PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS; iptables -t nat -F FORWARDS; iptables -t nat -X FORWARDS; iptables -D INPUT -j DROP; iptables -D INPUT -m state --state INVALID -j DROP; iptables -D FORWARD -m state --state INVALID -j DROP; iptables -D FORWARD ! -i br0 -o eth2.2 -j DROP; iptables -D FORWARD -j DROP; iptables -D FORWARD -i ! br0 -o eth0 -j DROP; iptables -D FORWARD -i ! br0 -o ppp0 -j DROP'], response => {
        console.log("-- Firewall FLUSH --");
    });

    queue.push(['iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && iptables -t nat -N FORWARDS && iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'], response => {
        console.log("-- Firewall ACCEPT --");

        telnet_ready = true;
    });

})

connection.on('timeout', () => {
    console.log('socket timeout!')
    //connection.end();
});

connection.on('close', () => {
    console.log('connection closed');
});

await connection.connect(params)
/////// TELNET

/////// QUEUE
let tasks = [];

function run_command(cmd, callback) {
    tasks.push(cmd);
    callback('');
}

queue.drain(() => {
    queue.pause();

    const cmds = tasks.join('; ');

    connection.exec(cmds, (err) => {
        if (err) {
            debugOut(err);
        }

        tasks = [];

        console.log("-- All tasks are complete --");

        queue.resume();
    });
});

queue.concurrency = 10;
/////// QUEUE

const domains_map = [];

for (let i = 0; i < 9000; i++) {
    domains_map[i] = 1;
}

const debugOut = console.log.bind(console);

const STATES = {
    handshake: 0,
    request: 1,
    forwarding: 2
};

function expandAndCopy(old, newer) {
    if (!old) {
        return newer;
    }

    const newBuf = new Buffer(old.length + newer.length);
    old.copy(newBuf);
    newer.copy(newBuf, old.length);

    return newBuf;
}

export default class Argyle extends EventEmitter {
    socksVersion = 5

    constructor(port = 8080, host = '127.0.0.1', debug) {
        super();

        if (!!debug) {
            this._debug = debugOut
        } else {
            this._debug = () => {
            }
        }

        this.serverSock = net.createServer()
        this.serverSock
            .on('listening', () => {
                const addr = this.serverSock.address();
                this._debug('socks server listening on %s:%s', addr.address, addr.port)
            })
            .on('connection', client => {
                this.handleConnection(client)
            })

        this.serverSock.listen(port, host)
    }

    handleConnection(client) {
        const handlers = {};
        const self = this;
        let curState = STATES.handshake;

        function onClientData(chunk) {
            handlers[curState](chunk)
        }

        client
            .on('end', () => {
            })
            .on('error', err => {
            })
            .on('data', onClientData)

        let buffer = null;

        handlers[STATES.handshake] = chunk => {
            buffer = expandAndCopy(buffer, chunk)

            if (buffer.length < 2) {
                return
            }

            const socksVersion = buffer[0];

            if (socksVersion !== this.socksVersion) {
                self._debug('unsupported client version: %d', socksVersion)
                return client.end()
            }

            const nMethods = buffer[1];

            if (buffer.length < nMethods + 2) {
                return;
            }

            for (let i = 0; i < nMethods; i++) {
                // try to find the no-auth method type, and if found, choose it
                if (buffer[i + 2] === 0) {
                    client.write(new Buffer([0x05, 0x00]))
                    curState++

                    if (buffer.length > nMethods + 2) {
                        const newChunk = buffer.slice(nMethods + 2);
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

        let proxyBuffers = [];

        handlers[STATES.request] = async chunk => {
            buffer = expandAndCopy(buffer, chunk)

            if (buffer.length < 4) {
                return
            }

            const socksVersion = buffer[0];
            if (socksVersion !== this.socksVersion) {
                self._debug('unsupported client version: %d', socksVersion)
                return client.end()
            }

            const cmd = buffer[1];

            if (cmd !== 0x01) {
                self._debug('unsupported command: %d', cmd)
                return client.end(new Buffer([0x05, 0x01]))
            }

            const addressType = buffer[3];
            let host;
            let port;
            let responseBuf;

            if (addressType === 0x01) { // ipv4
                // 4 for host + 2 for port
                if (buffer.length < 10) {
                    return
                }

                host = util.format('%d.%d.%d.%d', buffer[4], buffer[5], buffer[6], buffer[7])
                port = buffer.readUInt16BE(8)
                responseBuf = new Buffer(10)
                buffer.copy(responseBuf, 0, 0, 10)
                buffer = buffer.slice(10)
            } else if (addressType === 0x03) { // dns
                // if no length presents yet
                if (buffer.length < 5) {
                    return
                }

                const addrLength = buffer[4];

                // host + port
                if (buffer.length < 5 + addrLength + 2) {
                    return
                }

                host = buffer.toString('utf8', 5, 5 + addrLength)
                port = buffer.readUInt16BE(5 + addrLength)
                responseBuf = new Buffer(5 + addrLength + 2)
                buffer.copy(responseBuf, 0, 0, 5 + addrLength + 2)
                buffer = buffer.slice(5 + addrLength + 2)
            } else if (addressType === 0x04) { // ipv6
                // 16 for host + 2 for port
                if (buffer.length < 22) {
                    return
                }

                host = buffer.slice(4, 20)
                port = buffer.readUInt16BE(20)
                responseBuf = new Buffer(22)
                buffer.copy(responseBuf, 0, 0, 22)
                buffer = buffer.slice(22);
            } else {
                self._debug('unsupported address type: %d', addressType)

                return client.end(new Buffer([0x05, 0x01]))
            }

            self._debug('Request to %s:%s', host, port)
            curState++

            client.pause()

            if (!telnet_ready) {
                return client.end(new Buffer([0x05, 0x01]))
            }

            const dest_host = `${host}:${port}`;
            let connected = false;
            let req_port;

            if (domains_map.includes(dest_host)) {
                req_port = domains_map.indexOf(dest_host);

                console.log(`Found (${req_port}): ${params.host}:${req_port} = ${dest_host}`);
            } else {
                domains_map.push(dest_host);
                req_port = domains_map.indexOf(dest_host);

                await queue.push([`iptables -t nat -I FORWARDS -p TCP --dport ${req_port} -j DNAT --to "${host}":${port}; iptables -t nat -D POSTROUTING -d "${host}" -p TCP --dport ${port} -j MASQUERADE; iptables -t nat -I POSTROUTING -d "${host}" -p TCP --dport ${port} -j MASQUERADE`]);

                console.log(`Added (${req_port}): ${params.host}:${req_port} = ${dest_host}`);
            }

            const dest = net.createConnection(req_port, params.host, () => {
                responseBuf[1] = 0
                responseBuf[2] = 0

                client.write(responseBuf) // emit success to a client
                client.removeListener('data', onClientData)
                client.resume()

                self.emit('connected', client, dest)
                connected = true

                if (buffer && buffer.length) {
                    client.emit(buffer)
                    buffer = null
                }

                // re-emit any leftover data for proxy to handle
                for (let j = 0; j < proxyBuffers.length; j++) {
                    client.emit('data', proxyBuffers[i])
                }

                proxyBuffers = []
            })
                .once('error', err => {
                    if (!connected) {
                        client.end(new Buffer([0x05, 0x01]))
                    }
                })
                .once('close', () => {
                    if (!connected) {
                        client.end()
                    }
                })
                .once('timeout', () => {
                    if (!connected) {
                        client.end()
                    }
                });
        }

        handlers[STATES.forwarding] = chunk => {
            proxyBuffers.push(chunk);
        }
    }
}
