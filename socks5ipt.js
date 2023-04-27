import net from 'node:net';
import dns from 'node:dns';
import util from 'node:util';
import {Buffer} from 'node:buffer';
import {EventEmitter} from 'node:events';
import {Telnet} from 'telnet-client';
import async from 'async';

const debugOut = console.log.bind(console);

let params = process.argv.slice(2)

if (params.length) {
    params = JSON.parse(Buffer.from(params, 'base64'));
} else {
    params = {
        host: '192.168.99.207',
        port: 23,
        shellPrompt: /(#)s.*$/g,
        loginPrompt: /login[: ]*$/i,
        username: 'root',
        password: 'root',
        timeout: 5000
    };
}

const queue = async.cargo((telnetCommands, callback) => {
    queue.pause();
    const commands = telnetCommands.join('; ');

    connection.exec(commands, (err) => {
        if (err) {
            debugOut(err);
        }

        if (telnetCommands.length > 1) {
            console.log(commands);
            console.log(`-- Processed ${telnetCommands.length} commands --`);
        }

        queue.resume();

        callback();
    })
        .then();
}, 10);

const connection = new Telnet();
let telnetReady = false;
connection.on('ready', async () => {
    console.log("-- Telnet connected --");

    await queue.push(
        'iptables -D INPUT -p tcp --destination-port 9000:20000 -j ACCEPT;' +
        'iptables -D FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT;' +
        'iptables -t nat -D PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS;' +
        'iptables -t nat -F FORWARDS; iptables -t nat -X FORWARDS;' +
        'iptables -D INPUT -j DROP; iptables -D INPUT -m state --state INVALID -j DROP;' +
        'iptables -D FORWARD -m state --state INVALID -j DROP;' +
        'iptables -D FORWARD ! -i br0 -o eth2.2 -j DROP;' +
        'iptables -D FORWARD -j DROP; iptables -D FORWARD -i ! br0 -o eth0 -j DROP;' +
        'iptables -D FORWARD -i ! br0 -o ppp0 -j DROP'
    );

    console.log("-- Firewall FLUSH --");

    await queue.push(
        'iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
        'iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
        'iptables -t nat -N FORWARDS && ' +
        'iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'
    );

    console.log("-- Firewall ACCEPT --");

    telnetReady = true;
    queue.concurrency = 10;
})

connection.on('timeout', () => {
    console.log('socket timeout!')
    //connection.end();
});

connection.on('error', () => {
    console.log('connection error');
});
connection.on('close', () => {
    console.log('connection closed');
});

try {
    await connection.connect(params)
} catch (e) {
    console.log('Telnet:', params.host, params.port, e.toString());
    process.exit(1);
}

const domainsMap = [];

for (let i = 0; i < 9000; i++) {
    domainsMap[i] = 1;
}

export default class Socks5ipt extends EventEmitter {
    socksVersion = 5;
    STATES = {
        handshake: 0,
        request: 1,
        forwarding: 2
    };
    _debug = () => {
    };

    constructor(port = 1080, host = '127.0.0.1', debug) {
        super();

        if (!!debug) {
            this._debug = debugOut
        }

        this.serverSock = net.createServer()
        this.serverSock
            .on('listening', () => {
                const addr = this.serverSock.address();

                if (typeof addr === 'object') {
                    this._debug('socks server listening on %s:%s', addr.address, addr.port)
                } else {
                    this._debug('socks server listening on %s:%s', addr)
                }
            })
            .on('connection', client => {
                this.handleConnection(client)
            })

        this.serverSock.listen(port, host)
    }

    handleConnection(client) {
        const handlers = {};
        const self = this;
        let curState = this.STATES.handshake;

        function onClientData(chunk) {
            handlers[curState](chunk)
        }

        client
            .on('end', () => {
            })
            .on('error', err => {
                console.log(err);
            })
            .on('data', onClientData)

        let buffer = Buffer.allocUnsafe(0);

        handlers[this.STATES.handshake] = chunk => {
            buffer = Buffer.concat([buffer, chunk]);

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
                    client.write(Buffer.from([0x05, 0x00]))
                    curState++

                    if (buffer.length > nMethods + 2) {
                        const newChunk = buffer.slice(nMethods + 2);
                        buffer = Buffer.allocUnsafe(0);
                        handlers[this.STATES.request](newChunk)
                    }

                    buffer = Buffer.allocUnsafe(0);

                    return
                }
            }

            self._debug('No supported auth methods found, disconnecting.')
            client.end(Buffer.from([0x05, 0xff]))
        }

        let proxyBuffers = [];

        handlers[this.STATES.request] = async chunk => {
            buffer = Buffer.concat([buffer, chunk]);

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
                return client.end(Buffer.from([0x05, 0x01]))
            }

            const addressType = buffer[3];
            let host;
            let port;
            let responseBuf;

            switch (addressType) {
                // ipv4
                case 0x01:
                    // 4 for host + 2 for port
                    if (buffer.length < 10) {
                        return
                    }

                    host = util.format('%d.%d.%d.%d', buffer[4], buffer[5], buffer[6], buffer[7])
                    port = buffer.readUInt16BE(8)
                    responseBuf = Buffer.alloc(10)
                    buffer.copy(responseBuf, 0, 0, 10)
                    buffer = buffer.slice(10)
                    break;
                // dns
                case 0x03:
                    // if no length presents yet
                    if (buffer.length < 5) {
                        return
                    }

                    const addrLength = buffer[4];

                    // host + port
                    if (buffer.length < 5 + addrLength + 2) {
                        return
                    }

                    host = buffer.slice(5, 5 + addrLength).toString('utf8')

                    try {
                        host = await new Promise((resolve, reject) => {
                            dns.lookup(host, {family: 4}, (err, address) => {
                                if (err) {
                                    return reject(err);
                                }

                                resolve(address);
                            });
                        });

                        console.log(host);
                    } catch (e) {
                        self._debug(e);

                        return client.end(Buffer.from([0x05, 0x01]))
                    }

                    port = buffer.readUInt16BE(5 + addrLength)
                    responseBuf = Buffer.alloc(5 + addrLength + 2)
                    buffer.copy(responseBuf, 0, 0, 5 + addrLength + 2)
                    buffer = buffer.slice(5 + addrLength + 2)
                    break;
                // ipv6
                case 0x04:
                    // 16 for host + 2 for port
                    if (buffer.length < 22) {
                        return
                    }

                    host = buffer.slice(4, 20)
                    port = buffer.readUInt16BE(20)
                    responseBuf = Buffer.alloc(22)
                    buffer.copy(responseBuf, 0, 0, 22)
                    buffer = buffer.slice(22);
                    break;
                default:
                    self._debug('unsupported address type: %d', addressType)

                    return client.end(Buffer.from([0x05, 0x01]))
            }

            self._debug('Request to %s:%s', host, port)
            curState++

            client.pause()

            if (!telnetReady) {
                return client.end(Buffer.from([0x05, 0x01]))
            }

            const destHost = `${host}:${port}`;
            let connected = false;
            let reqPort;

            if (domainsMap.includes(destHost)) {
                reqPort = domainsMap.indexOf(destHost);

                console.log(`Found (${reqPort}): ${params.host}:${reqPort} = ${destHost}`);
            } else {
                domainsMap.push(destHost);
                reqPort = domainsMap.indexOf(destHost);

                await queue.push(
                    `iptables -t nat -I FORWARDS -p TCP --dport ${reqPort} -j DNAT --to ${host}:${port}; ` +
                    `iptables -t nat -D POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE; ` +
                    `iptables -t nat -I POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE`
                );

                console.log(`Added (${reqPort}): ${params.host}:${reqPort} = ${destHost}`);
            }

            const dest = net.createConnection(reqPort, params.host, () => {
                responseBuf[1] = 0
                responseBuf[2] = 0

                client.write(responseBuf) // emit success to a client
                client.removeListener('data', onClientData)
                client.resume()

                self.emit('connected', client, dest)
                connected = true

                if (buffer && buffer.length) {
                    client.emit(buffer)
                    buffer = Buffer.allocUnsafe(0);
                }

                // re-emit any leftover data for proxy to handle
                for (let j = 0; j < proxyBuffers.length; j++) {
                    client.emit('data', proxyBuffers[j])
                }

                proxyBuffers = []
            })
                .once('error', err => {
                    if (!connected) {
                        client.end(Buffer.from([0x05, 0x01]))
                    }

                    console.log(err);
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

        handlers[this.STATES.forwarding] = chunk => {
            proxyBuffers.push(chunk);
        }
    }
}
