# SOCKS5 Proxy Server

This project is a SOCKS5 proxy server designed to utilize a home router as a proxy server. By leveraging the router's SSH/Telnet command interface, the server dynamically sets NAT (Network Address Translation) rules for connections passing through the SOCKS5 proxy. This setup allows users to use their home router as a proxy server from the WAN (Wide Area Network).

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Environment Variables](#environment-variables)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/jstarstech/socks5-proxy-server.git
   cd socks5-proxy-server
   ```

2. Install the dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory and set the required environment variables (see [Environment Variables](#environment-variables)).

## Usage

To start the SOCKS5 proxy server, run the following command, providing the necessary parameters as a base64 encoded JSON string:

```
node src/app.js <base64_encoded_parameters>
```

### Example

To encode the parameters:
```json
{
    "host": "192.168.1.1",
    "username": "root",
    "password": "root"
}
```
You can use a tool or a command like:
```
echo -n '{"host":"192.168.1.1","username":"root","password":"root"}' | base64
```

Then run:
```
node app.js eyJob3N0IjogIjE5Mi4xNjguMS4xIiwgInVzZXJuYW1lIjogInJvb3QiLCAicGFzc3dvcmQiOiAicm9vdCJ9
```

## Environment Variables

- `PORT`: The port on which the server will listen (default: 1080).
- `HOST`: The host address for the server (default: 0.0.0.0).
