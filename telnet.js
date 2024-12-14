import async from 'async';
import { Telnet } from 'telnet-client';

export class TelnetInterface {
    hostsMap = [];
    telnetReady = false;
    queue;
    connection;
    params = {
        port: 23,
        shellPrompt: /(#)s.*$/g,
        loginPrompt: /login[: ]*$/i,
        timeout: 5000
    };

    constructor(params) {
        if (!params) {
            throw new Error('Params not provided');
        }

        this.params = { ...this.params, ...params };

        for (let i = 0; i < 9000; i++) {
            this.hostsMap[i] = 1;
        }

        this.queue = async.cargo(async telnetCommands => {
            this.queue.pause();
            const commands = telnetCommands.join('; ');

            console.log('Telnet:', commands);

            try {
                await this.connection.exec(commands);

                console.log('Telnet:', `Executed ${telnetCommands.length} commands`);
            } catch (e) {
                console.log('Telnet:', e.toString());
            }

            this.queue.resume();
        }, 10);

        this.connection = new Telnet();

        this.connection.on('ready', async () => {
            console.log('Telnet: connected');

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

            console.log('Telnet: Firewall FLUSH');

            await this.queue.push(
                'iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                    'iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                    'iptables -t nat -N FORWARDS && ' +
                    'iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'
            );

            console.log('Telnet: Firewall ACCEPT');

            this.telnetReady = true;
        });

        this.connection.on('error', () => {
            console.log('Telnet: connection error');
        });

        this.connection.on('close', () => {
            console.log('Telnet: connection closed. Exit application');

            process.exit(1);
        });
    }

    async init() {
        try {
            await this.connection.connect(this.params);
        } catch (e) {
            this.telnetReady = false;

            console.log('Telnet:', this.params.host, this.params.port, e.toString());
        }
    }

    async hostMap(host, port) {
        if (!this.telnetReady) {
            return {
                err: new Error('Telnet connection not ready'),
                host: null,
                port: null
            };
        }

        const destHostPort = `${host}:${port}`;

        let destPort;

        if (this.hostsMap.includes(destHostPort)) {
            destPort = this.hostsMap.indexOf(destHostPort);

            console.log(`Found: ${this.params.host}:${destPort} => ${destHostPort}`);
        } else {
            this.hostsMap.push(destHostPort);
            destPort = this.hostsMap.indexOf(destHostPort);

            await this.queue.push(
                `iptables -t nat -D FORWARDS -p TCP --dport ${destPort} -j DNAT --to ${host}:${port}; ` +
                    `iptables -t nat -I FORWARDS -p TCP --dport ${destPort} -j DNAT --to ${host}:${port}; ` +
                    `iptables -t nat -D POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE; ` +
                    `iptables -t nat -I POSTROUTING -d ${host} -p TCP --dport ${port} -j MASQUERADE`
            );

            console.log(`Added: ${this.params.host}:${destPort} = ${destHostPort}`);
        }

        return {
            err: null,
            destHost: this.params.host,
            destPort
        };
    }
}
