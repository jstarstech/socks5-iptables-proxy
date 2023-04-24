import express from 'express';
import async from 'async';
import http from 'http';
import url from 'url';
import xpath from 'xpath';
import {DOMParser} from 'xmldom';
import fs from 'fs';

export default () => {
};

const app = express();

let result = '';

/////// QUEUE
function run_command(hurl, callback) {
    const ip = url.parse(hurl);
    const options = {
        hostname: ip.hostname,
        auth: ip.auth,
        port: ip.port,
        path: ip.pathname,
        agent: false,
        method: 'GET'
    };

    const request = http.get(options, res => {
        let pageData = '';

        res.resume();

        res.on('data', chunk => {
            if (res.statusCode === 200) {
                pageData += chunk;
            }
        });

        res.on('end', () => {
            console.log(`finish to fetch id: ${ip.hostname}`);

            /* fs.writeFile('message' + ip.hostname + '.html', pageData, function (err) {
                if (err) throw err;
            }); */

            let live = false;

            if (pageData) {
                const doc = new DOMParser({
                    errorHandler() {
                    }
                }).parseFromString(pageData);
                const nodes = xpath.select('//*/title', doc);

                if (nodes[0]) {
                    live = true;
                    console.log(nodes[0].firstChild.data);
                }

                /* fs.writeFile('message' + options.pageId +'.html', pageData, function (err) {
                    if (err) throw err;
                }); */
            }

            result += `${hurl}n`;

            callback();
        });
    }).on('error', e => {
        //console.log("Error: " + options.hostname + "n" + e.message);
        //result += "Error: " + options.hostname + "n" + e.message + "n";
        callback();
    });

    request.setTimeout(5000, () => {
        request.abort();
    });
}

const queue = async.queue(run_command, 1);

/* queue.drain = function() {
    console.log("-- All tasks are complete --");
}; */

queue.concurrency = 100;
/////// QUEUE

app.get('/get_titles', (req, res) => {
    const hosts = fs.readFileSync('hosts.txt').toString().split("rn");

    queue.push(hosts);

    queue.drain = () => {
        res.send(result);
        console.log("-- All tasks are complete --");
    };
});

app.use(({stack}, req, res, next) => {
    console.error(stack);
    res.send(500, 'Something broke!');
});

const server = app.listen(8088, () => {
    console.log('Listening on port %d', server.address().port);
});
