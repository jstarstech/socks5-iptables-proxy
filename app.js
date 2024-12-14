import { Buffer } from 'node:buffer';
import Socks5ipt from './socks5ipt.js';
import { SSHInterface } from './ssh.js';
import dotenv from 'dotenv';

dotenv.config();

let params = process.argv.slice(2);

if (params.length) {
    params = JSON.parse(Buffer.from(params.join(''), 'base64').toString());
} else {
    console.error('No parameters provided. Exiting...');
    process.exit(1);
}

const port = process.env.PORT || 1080;
const host = process.env.HOST || '0.0.0.0';

const socks5ipt = new Socks5ipt(port, host, true);

// const telnetInterface = new TelnetInterface(params);
// await telnetInterface.init();
// socks5ipt.hostMap = telnetInterface.hostMap.bind(telnetInterface);

const sshInterface = new SSHInterface(params);
await sshInterface.init();
socks5ipt.hostMap = sshInterface.hostMap.bind(sshInterface);

socks5ipt.on('connected', (req, dest) => {
    req.once('error', err => {
        dest.end();
        req.end();
    }).once('close', () => {
        dest.end();
        req.end();
    });

    dest.once('error', err => {
        dest.end();
        req.end();
    }).once('close', () => {
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
