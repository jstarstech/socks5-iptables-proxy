import async from "async";
import {Client} from "ssh2";

export class SSHInterface {
    hostsMap = [];
    sshReady = false;
    queue;
    connection;
    params = {
        port: 22,
        timeout: 5000
    };

    constructor(params) {
        if (!params) {
            throw new Error('Params not provided');
        }

        this.params = {...this.params, ...params};

        for (let i = 0; i < 9000; i++) {
            this.hostsMap[i] = 1;
        }

        this.queue = async.cargo(async (sshCommands) => {
            this.queue.pause();
            const commands = sshCommands.join('; ');

            console.log('SSH:', commands);

            try {
                await new Promise((resolve, reject) => {
                    this.connection.exec(commands, { pty: true }, (err, stream) => {
                        if (err) {
                            return reject(err);
                        }

                        stream.on('close', (code, signal) => {
                            // console.log('Stream :: close :: code: ' + code + ', signal: ' + signal);

                            resolve();
                        });

                        stream.on('data', (data) => {
                            // console.log('STDOUT: ' + data);
                        });

                        stream.stderr
                            .on('data', (data) => {
                                // console.log('STDERR: ' + data);
                            });
                    });
                });

                console.log('SSH:', `Executed ${sshCommands.length} commands`);
            } catch (e) {
                console.log('SSH:', e.toString());
            }

            this.queue.resume();
        }, 10);

        this.connection = new Client();

        this.connection.on('ready', async () => {
            console.log('SSH: connected');

            await this.queue.push(
                'iptables -D INPUT -p tcp --destination-port 9000:20000 -j ACCEPT;' +
                'iptables -D FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT;' +
                'iptables -t nat -D PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS;' +
                'iptables -t nat -F FORWARDS;' +
                'iptables -t nat -X FORWARDS;' +
                'iptables -D INPUT -j DROP;' +
                'iptables -D INPUT -m state --state INVALID -j DROP;' +
                'iptables -D FORWARD -m state --state INVALID -j DROP;' +
                'iptables -D FORWARD ! -i br0 -o eth2.2 -j DROP;' +
                'iptables -D FORWARD -j DROP;' +
                'iptables -D FORWARD -i ! br0 -o eth0 -j DROP;' +
                'iptables -D FORWARD -i ! br0 -o ppp0 -j DROP;'
            );

            console.log('SSH: Firewall FLUSH');

            await this.queue.push(
                'iptables -I INPUT -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                'iptables -I FORWARD -p tcp --destination-port 9000:20000 -j ACCEPT && ' +
                'iptables -t nat -N FORWARDS && ' +
                'iptables -t nat -I PREROUTING -p tcp --destination-port 9000:20000 -j FORWARDS'
            );

            console.log('SSH: Firewall ACCEPT');

            this.sshReady = true;
        })

        this.connection.on('error', (err) => {
            console.log('SSH: connection error', err.toString());
        });

        this.connection.on('close', () => {
            console.log('SSH: connection closed. Exit application');
        });
    }

    async init() {
        try {
            await this.connection.connect(this.params)
        } catch (e) {
            this.sshReady = false;

            console.log('SSH:', this.params.host, this.params.port, e.toString());
        }
    }

    async hostMap(host, port) {
        if (!this.sshReady) {
            return {
                err: new Error('SSH connection not ready'), host: null, port: null
            }
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
            err: null, destHost: this.params.host, destPort
        }
    }
}
