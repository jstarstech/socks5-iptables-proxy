import Socks5ipt from './socks5ipt.js';
import {Buffer} from "node:buffer";
import async from "async";
import {Telnet} from "telnet-client";

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
            console.log(err);
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

const hostsMap = [];

for (let i = 0; i < 9000; i++) {
    hostsMap[i] = 1;
}

const socks5ipt = new Socks5ipt(1084, '0.0.0.0', true);

socks5ipt.hostMap = async (host, port) => {
    if (!telnetReady) {
        return {
            err: new Error('Telnet connection not ready'), host: null, port: null
        }
    }

    const destHostPort = `${host}:${port}`;

    let reqPort;

    if (hostsMap.includes(destHostPort)) {
        reqPort = hostsMap.indexOf(destHostPort);

        console.log(`Found: ${params.host}:${reqPort} => ${destHostPort}`);
    } else {
        hostsMap.push(destHostPort);
        reqPort = hostsMap.indexOf(destHostPort);

        await queue.push(
            `iptables -t nat -I FORWARDS -p TCP --dport ${reqPort} -j DNAT --to ${host}:${port}; ` +
            `iptables -t nat -D POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE; ` +
            `iptables -t nat -I POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE`
        );

        console.log(`Added: ${params.host}:${reqPort} = ${destHostPort}`);
    }

    return {
        err: null, destHost: params.host, destPort: reqPort
    }
}

socks5ipt.on('connected', (req, dest) => {
    req
        .once('error', err => {
            dest.end();
            req.end();
        })
        .once('close', () => {
            dest.end();
            req.end();
        });

    dest
        .once('error', err => {
            dest.end();
            req.end();
        })
        .once('close', () => {
            dest.end();
            req.end();
        });

    req.on('data', chunk => {
        dest.write(chunk);
    });

    dest.on('data', chunk => {
        req.write(chunk);
    });
});
