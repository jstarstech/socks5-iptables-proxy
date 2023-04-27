import net from 'node:net';
import dns from 'node:dns';
import util from 'node:util';
import {Buffer} from 'node:buffer';
import {EventEmitter} from 'node:events';

export default class Socks5ipt extends EventEmitter {
    socksVersion = 5;
    STATES = {
        handshake: 0,
        request: 1,
        forwarding: 2
    };
    _debug = () => {
    };
    hostMap = async (host, port) => {
        return {
            err: null, host, port
        }
    };

    constructor(port = 1080, host = '127.0.0.1', debug = false) {
        super();

        if (debug) {
            this._debug = console.log.bind(console);
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

            const [err, destHost, destPort] = await this.hostMap(host, port);

            if (!err) {
                return client.end(Buffer.from([0x05, 0x01]))
            }

            let connected = false;

            const dest = net.createConnection(destHost, destPort, () => {
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
