import { Buffer } from 'node:buffer';
import Socks5ipt from './socks5ipt.js';
import { SSHInterface } from './ssh.js';

let params = process.argv.slice(2);

if (params.length) {
    params = JSON.parse(Buffer.from(params, 'base64'));
} else {
    params = {
        host: '192.168.99.207',
        username: 'root',
        password: 'root'
    };
}

const socks5ipt = new Socks5ipt(1084, '0.0.0.0', true);

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
