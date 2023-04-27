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

export class TelnetInterface {
    hostsMap = [];
    telnetReady = false;
    queue;
    connection;

    constructor() {
        for (let i = 0; i < 9000; i++) {
            this.hostsMap[i] = 1;
        }

        this.queue = async.cargo((telnetCommands, callback) => {
            this.queue.pause();
            const commands = telnetCommands.join('; ');

            this.connection.exec(commands, (err) => {
                if (err) {
                    console.log(err);
                }

                if (telnetCommands.length > 1) {
                    console.log(commands);
                    console.log(`-- Processed ${telnetCommands.length} commands --`);
                }

                this.queue.resume();

                callback();
            })
                .then();
        }, 10);

        this.connection = new Telnet();

        this.connection.on('ready', async () => {
            console.log("-- Telnet connected --");

            await this.queue.push(
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

            await this.queue.push(
                'iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                'iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                'iptables -t nat -N FORWARDS && ' +
                'iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'
            );

            console.log("-- Firewall ACCEPT --");

            this.telnetReady = true;
        })

        this.connection.on('timeout', () => {
            console.log('socket timeout!')
            //connection.end();
        });

        this.connection.on('error', () => {
            console.log('connection error');
        });

        this.connection.on('close', () => {
            console.log('connection closed');
        });
    }

    async init() {
        try {
            await this.connection.connect(params)
        } catch (e) {
            console.log('Telnet:', params.host, params.port, e.toString());
            process.exit(1);
        }
    }

    async hostMap(host, port) {
        if (!this.telnetReady) {
            return {
                err: new Error('Telnet connection not ready'), host: null, port: null
            }
        }

        const destHostPort = `${host}:${port}`;

        let destPort;

        if (this.hostsMap.includes(destHostPort)) {
            destPort = this.hostsMap.indexOf(destHostPort);

            console.log(`Found: ${params.host}:${destPort} => ${destHostPort}`);
        } else {
            this.hostsMap.push(destHostPort);
            destPort = this.hostsMap.indexOf(destHostPort);

            await this.queue.push(
                `iptables -t nat -I FORWARDS -p TCP --dport ${destPort} -j DNAT --to ${host}:${port}; ` +
                `iptables -t nat -D POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE; ` +
                `iptables -t nat -I POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE`
            );

            console.log(`Added: ${params.host}:${destPort} = ${destHostPort}`);
        }

        return {
            err: null, destHost: params.host, destPort
        }
    }
}
