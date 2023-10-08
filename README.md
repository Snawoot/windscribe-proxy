windscribe-proxy
================

Standalone Windscribe proxy client. Younger brother of [opera-proxy](https://github.com/Snawoot/opera-proxy/).

Just run it and it'll start a plain HTTP proxy server forwarding traffic through Windscribe proxies of your choice.
By default the application listens on 127.0.0.1:28080.

## Features

* Cross-platform (Windows/Mac OS/Linux/Android (via shell)/\*BSD)
* Uses TLS for secure communication with upstream proxies
* Zero configuration
* Simple and straightforward

## Installation

#### Binaries

Pre-built binaries are available [here](https://github.com/Snawoot/windscribe-proxy/releases/latest).

#### Build from source

Alternatively, you may install windscribe-proxy from source. Run the following within the source directory:

```
make install
```

#### Docker

A docker image is available as well. Here is an example of running windscribe-proxy as a background service:

```sh
docker run -d \
    --security-opt no-new-privileges \
    -p 127.0.0.1:28080:28080 \
    --restart unless-stopped \
    --name windscribe-proxy \
    yarmak/windscribe-proxy
```

## Usage

List available locations:

```
windscribe-proxy -list-locations
```

Run proxy via location of your choice:

```
windscribe-proxy -location Germany/Frankfurt
```

Also it is possible to export proxy addresses and credentials:

```
windscribe-proxy -list-proxies
```

## List of arguments

| Argument | Type | Description |
| -------- | ---- | ----------- |
| 2fa | String | 2FA code for login |
| auth-secret | String | client auth secret (default `952b4412f002315aa50751032fcaab03`) |
| bind-address | String | HTTP proxy listen address (default `127.0.0.1:28080`) |
| cafile | String | use custom CA certificate bundle file |
| fake-sni | String | fake SNI to use to contact windscribe servers (default "com") |
| force-cold-init | - | force cold init |
| list-locations | - | list available locations and exit |
| list-proxies | - | output proxy list and exit |
| location | String | desired proxy location. Default: best location |
| password | String | password for login |
| proxy | String | sets base proxy to use for all dial-outs. Format: `<http\|https\|socks5\|socks5h>://[login:password@]host[:port]` Examples: `http://user:password@192.168.1.1:3128`, `socks5://10.0.0.1:1080` |
| resolver | String | Use DNS/DoH/DoT/DoQ resolver for all dial-outs. See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. Examples: `https://1.1.1.1/dns-query`, `quic://dns.adguard.com` |
| state-file | String | file name used to persist Windscribe API client state. Default: `wndstate.json` |
| timeout | Duration | timeout for network operations. Default: `10s` |
| username | String | username for login |
| verbosity | Number | logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical). Default: `20` |
| version | - | show program version and exit |

## See also

* [Project wiki](https://github.com/Snawoot/windscribe-proxy/wiki)
* [Community in Telegram](https://t.me/alternative_proxy)
