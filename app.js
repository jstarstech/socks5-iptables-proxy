import argyle from './packages/argyle';
//import scan from './scan';

const socks5_server = argyle(1084, '0.0.0.0', true);

socks5_server.on('connected', (req, dest) => {
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
