import Socks5ipt from './socks5ipt.js';
import {TelnetInterface} from './telnet.js';

const telnetInterface = new TelnetInterface();
await telnetInterface.init();

const socks5ipt = new Socks5ipt(1084, '0.0.0.0', true);
socks5ipt.hostMap = telnetInterface.hostMap.bind(telnetInterface);

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
