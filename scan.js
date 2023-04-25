import express from 'express';
import async from 'async';
import http from 'http';
import url from 'url';
import {DOMParser} from '@xmldom/xmldom'
import fs from 'fs';

let result = '';

function run_command(hurl, callback) {
    const ip = url.parse(hurl);
    const options = {
        hostname: ip.hostname,
        auth: ip.auth,
        port: ip.port,
        path: ip.pathname,
        agent: false,
        method: 'GET',
        // timeout: 1000
    };
    let live = false;
    let title = false;

    const request = http.get(options, res => {
        let pageData = '';

        res.resume();

        res.on('data', chunk => {
            if (res.statusCode === 200) {
                pageData += chunk;
            }
        });

        res.on('end', () => {
            console.log(`Finish to fetch: ${hurl}`);

            /* fs.writeFile('message' + ip.hostname + '.html', pageData, function (err) {
                if (err) throw err;
            }); */

            if (pageData) {
                const doc = new DOMParser({
                    errorHandler(err) {
                        console.log(err);
                    }
                })
                    .parseFromString(pageData, 'text/html');

                title = doc.getElementsByTagName('title').item(0).textContent

                if (title) {
                    live = true;
                    console.log(title);
                }

                /* fs.writeFile('message' + options.pageId +'.html', pageData, function (err) {
                    if (err) throw err;
                }); */
            }

            result += `${hurl} ${live ? 'up' : 'down'} Title: "${title}"<br />n`;

            callback();
        });
    });

    request.on('error', e => {
        //console.log("Error: " + options.hostname + "n" + e.message);
        //result += "Error: " + options.hostname + "n" + e.message + "n";

        result += `${hurl} ${live ? 'up' : 'down'}<br />n`;

        callback();
    });

    request.setTimeout(5000, () => {
        request.abort();
    });
}

const queue = async.queue(run_command, 1);
queue.concurrency = 100;


const app = express();

app.get('/get_titles', async (req, res) => {
    result = '';

    const hosts =
        fs
            .readFileSync('hosts.txt')
            .toString()
            .split("n")
            .filter((el) => el !== '');

    queue.drain(() => {
        res.write(result);
        res.end();
    });

    await queue.push(hosts);

    res.write(`<h1>Scan started! Queued ${hosts.length} hosts</h1>`)
});

app.use((req, res, next) => {
    res.status(404).send(
        "<h1>Page not found on the server</h1>")
})

const server = app.listen(8088, () => {
    console.log('Listening on port %d', server.address().port);
});
