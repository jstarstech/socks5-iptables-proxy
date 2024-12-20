import net from 'net';
import util from 'util';

const log = args => {
    console.log(args);
};

const info = console.info;
const errorLog = console.error;
const clients = [];
const SOCKS_VERSION = 5;

/*
 * Authentication methods
 ************************
 * o  X'00' NO AUTHENTICATION REQUIRED
 * o  X'01' GSSAPI
 * o  X'02' USERNAME/PASSWORD
 * o  X'03' to X'7F' IANA ASSIGNED
 * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 * o  X'FF' NO ACCEPTABLE METHODS
 */
const AUTHENTICATION = {
    NOAUTH: 0x00,
    GSSAPI: 0x01,
    USERPASS: 0x02,
    NONE: 0xff
};

/*
 * o  CMD
 *    o  CONNECT X'01'
 *    o  BIND X'02'
 *    o  UDP ASSOCIATE X'03'
 */
const REQUEST_CMD = {
    CONNECT: 0x01,
    BIND: 0x02,
    UDP_ASSOCIATE: 0x03
};

/*
 * o  ATYP   address type of following address
 *    o  IP V4 address: X'01'
 *    o  DOMAINNAME: X'03'
 *    o  IP V6 address: X'04'
 */
const ATYP = {
    IP_V4: 0x01,
    DNS: 0x03,
    IP_V6: 0x04
};

const Address = {
    read(buffer, offset) {
        if (buffer[offset] === ATYP.IP_V4) {
            return util.format(
                '%s.%s.%s.%s',
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
                buffer[offset + 4]
            );
        } else if (buffer[offset] === ATYP.DNS) {
            return buffer.toString('utf8', offset + 2, offset + 2 + buffer[offset + 1]);
        } else if (buffer[offset] === ATYP.IP_V6) {
            return buffer.slice(buffer[offset + 1], buffer[offset + 1 + 16]);
        }
    },
    sizeOf(buffer, offset) {
        if (buffer[offset] === ATYP.IP_V4) {
            return 4;
        } else if (buffer[offset] === ATYP.DNS) {
            return buffer[offset + 1];
        } else if (buffer[offset] === ATYP.IP_V6) {
            return 16;
        }
    }
};

function createSocksServer(cb) {
    const socksServer = net.createServer();
    socksServer.on('listening', () => {
        const address = socksServer.address();
        info('LISTENING %s:%s', address.address, address.port);
    });
    socksServer.on('connection', socket => {
        info('CONNECTED %s:%s', socket.remoteAddress, socket.remotePort);
        initSocksConnection.bind(socket)(cb);
    });
    return socksServer;
}

//
// socket is available as this
function initSocksConnection(on_accept) {
    // keep log of connected clients
    clients.push(this);

    // remove from clients on disconnect
    this.on('end', function () {
        const idx = clients.indexOf(this);
        if (idx !== -1) {
            clients.splice(idx, 1);
        }
    });
    this.on('error', e => {
        errorLog('%j', e);
    });

    // do a handshake
    this.handshake = handshake.bind(this);
    this.on_accept = on_accept; // No bind. We want 'this' to be the server, like it would be for net.createServer
    this.on('data', this.handshake);
}

function handshake(chunk) {
    this.removeListener('data', this.handshake);

    // SOCKS Version 5 is the only support version
    if (chunk[0] !== SOCKS_VERSION) {
        errorLog('handshake: wrong socks version: %d', chunk[0]);
        this.end();
    }

    // Number of authentication methods
    let method_count = chunk[1];

    this.auth_methods = [];
    // i starts on 1, since we've read chunk 0 & 1 already
    for (let i = 2; i < method_count + 2; i++) {
        this.auth_methods.push(chunk[i]);
    }
    log('Supported auth methods: %j', this.auth_methods);

    const resp = new Buffer(2);
    resp[0] = 0x05;
    if (this.auth_methods.includes(AUTHENTICATION.NOAUTH)) {
        log('Handing off to handleRequest');
        this.handleRequest = handleRequest.bind(this);
        this.on('data', this.handleRequest);
        resp[1] = AUTHENTICATION.NOAUTH;
        this.write(resp);
    } else {
        errorLog('Unsuported authentication method -- disconnecting');
        resp[1] = 0xff;
        this.end(resp);
    }
}

function handleRequest(chunk) {
    this.removeListener('data', this.handleRequest);
    let cmd = chunk[1];
    let address;
    let port;
    let offset = 3;
    // Wrong version!
    if (chunk[0] !== SOCKS_VERSION) {
        this.end('%d%d', 0x05, 0x01);
        errorLog('handleRequest: wrong socks version: %d', chunk[0]);
        return;
    } /* else if (chunk[2] == 0x00) {
      this.end(util.format('%d%d', 0x05, 0x01));
      errorLog('handleRequest: Mangled request. Reserved field is not null: %d', chunk[offset]);
      return;
  } */
    address = Address.read(chunk, 3);
    offset = 3 + Address.sizeOf(chunk, 3) + 2;
    port = chunk.readUInt16BE(offset);

    log('Request: type: %d -- to: %s:%s', chunk[1], address, port);

    if (cmd === REQUEST_CMD.CONNECT) {
        this.request = chunk;
        this.on_accept(this, port, address, proxyReady.bind(this));
    } else {
        this.end('%d%d', 0x05, 0x01);
    }
}

function proxyReady() {
    log('Indicating to the client that the proxy is ready');
    // creating response
    const resp = new Buffer(this.request.length);
    this.request.copy(resp);
    // rewrite response header
    resp[0] = SOCKS_VERSION;
    resp[1] = 0x00;
    resp[2] = 0x00;
    this.write(resp);
    log('Connected to: %s:%d', resp.toString('utf8', 4, resp.length - 2), resp.readUInt16BE(resp.length - 2));
}

export default {
    createServer: createSocksServer
};
