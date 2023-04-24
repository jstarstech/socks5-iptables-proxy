var express = require('express');
var async = require('async');
var http = require('http');
var url = require('url');
var app = express();
var xpath = require('xpath');
var dom = require('xmldom').DOMParser;
var fs = require('fs');

module.exports = function() {
}

var result = '';

/////// QUEUE
function run_command(hurl, callback) {
    var ip = url.parse(hurl);
    var options = {
        hostname: ip.hostname,
        auth: ip.auth,
        port: ip.port,
        path: ip.pathname,
        agent: false,
        method: 'GET'
    };

    var request = http.get(options, function(res) {
        var pageData = '';

        res.resume();

        res.on('data', function (chunk) {
            if(res.statusCode == 200) {
                pageData += chunk;
            }
        });

        res.on('end', function() {
            console.log("finish to fetch id: " + ip.hostname);

            /* fs.writeFile('message' + ip.hostname + '.html', pageData, function (err) {
                if (err) throw err;
            }); */

            var live = false;

            if (pageData) {
                var doc = new dom({errorHandler: function(){}}).parseFromString(pageData);
                var nodes = xpath.select('//*/title', doc)

                if (nodes[0]) {
                    live = true;
                    console.log(nodes[0].firstChild.data);
                }

                /* fs.writeFile('message' + options.pageId +'.html', pageData, function (err) {
                    if (err) throw err;
                }); */
            }

            result += hurl + "n";

            callback();
        });
    }).on('error', function(e) {
       //console.log("Error: " + options.hostname + "n" + e.message);
       //result += "Error: " + options.hostname + "n" + e.message + "n";
       callback();
    });

    request.setTimeout(5000, function() {
        request.abort();
    });
}

var queue = async.queue(run_command, 1);

/* queue.drain = function() {
    console.log("-- All tasks are complete --");
}; */

queue.concurrency = 100;
/////// QUEUE

app.get('/get_titles', function(req, res){
    var hosts = fs.readFileSync('hosts.txt').toString().split("rn");

    queue.push(hosts);

    queue.drain = function() {
        res.send(result);
        console.log("-- All tasks are complete --");
    };
});

app.use(function(err, req, res, next){
    console.error(err.stack);
    res.send(500, 'Something broke!');
});

var server = app.listen(8088, function() {
    console.log('Listening on port %d', server.address().port);
});
