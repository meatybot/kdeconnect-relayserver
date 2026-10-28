<!--
SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# kdeconnect-relayserver

A small relay server that lets [KDE Connect](https://kdeconnect.kde.org/) devices on different
networks reach each other. It is used by the KDE Connect forks
[meatybot/kdeconnect-kde](https://github.com/meatybot/kdeconnect-kde) (desktop) and
[meatybot/kdeconnect-android](https://github.com/meatybot/kdeconnect-android). It is not affiliated
with KDE.

The relay never sees device traffic in the clear. Devices run their normal TLS session end to end
through the relay and pin each other's certificates, then pair with the usual verification key.
The relay can see which devices are online, who connects to whom and how much data flows.

Each device that connects gets a *relay key* such as `ULJO-GBWQ-G4X3-LFX5-N5SH`, derived from its
public key. Typing that key on another device connected to the same relay connects the two.

The server depends only on QtCore and QtNetwork, so it runs on headless machines.

## Quick start

With Docker:

```sh
docker run -d --name kdeconnect-relay --restart unless-stopped \
    -p 1765:1765 -v kdeconnect-relay:/data \
    ghcr.io/meatybot/kdeconnect-relayserver:latest
```

Without Docker, from a release binary or a build:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=kdeconnect-relay" -keyout relay.key -out relay.crt
kdeconnect-relayserver --cert relay.crt --key relay.key
```

Open TCP port 1765 in your firewall. Then, on every device, set the relay address (`host:port`) in
the KDE Connect settings, or run `kdeconnect-cli --relay-server host:port` on the desktop. Enter
the other device's relay key under "Connect to device" (`kdeconnect-cli --connect <key>`), accept
the pairing request and compare the verification key on both screens. Paired devices reconnect
through the relay automatically when both are online.

[docs/hosting.md](docs/hosting.md) covers systemd, containers, certificates, firewalls, sizing and
what the relay operator can see.

## Options

Defaults in parentheses:

- `--cert <file>`, `--key <file>`: PEM certificate and private key (EC or RSA) of the server, required
- `--listen <address>`: address to bind (any)
- `--port <port>`: TCP port (1765)
- `--max-devices <n>`: registered devices (10000)
- `--max-connections-per-ip <n>`: concurrent connections per source IP (64)
- `--max-new-connections-per-ip <n>`: new connections per source IP and minute (30)
- `--max-tunnels-per-device <n>`: pending and active tunnels per device (16)
- `--tunnel-idle-timeout <seconds>`: close tunnels without traffic (600)
- `--verbose`: log registrations and tunnels, including relay keys
- `--version`, `--help`

All state is kept in memory. A restart disconnects every device, and devices reconnect on their own.

## Building

Requirements: CMake 3.22, a C++17 compiler and Qt 6.4 or later (Core, Network, and Test for the
tests). CI builds on Ubuntu 24.04 (Qt 6.4), Debian 13 (Qt 6.8) and Arch Linux.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

`cmake --install` installs the binary and the systemd unit
(`lib/systemd/system/kdeconnect-relayserver.service`, change it with `-DSYSTEMD_UNIT_DIR=...`).
Pass `-DINSTALL_SYSTEMD_UNIT=OFF` to skip the unit and `-DBUILD_TESTING=OFF` to skip the tests.

To build the container image locally: `docker build -t kdeconnect-relayserver .`

## Repository layout

| Path | Content |
|---|---|
| `src/relayserver.*` | the server |
| `src/relayprotocol.*` | key derivation, target parsing and message framing, shared with the desktop client |
| `src/main.cpp` | command line handling |
| `tests/` | protocol and server tests, run against the server over real sockets |
| `packaging/systemd/` | systemd unit template |
| `docker/`, `Dockerfile` | container image |
| `docs/protocol.md` | wire protocol and security model |
| `docs/hosting.md` | operator guide |
| `RELEASING.md` | how releases are made |

The desktop client includes this repository as a git submodule and compiles `src/relayprotocol.*`
and the server itself for its integration tests. Keep `src/relayprotocol.*` free of dependencies
beyond QtCore and QtNetwork, and bump the submodule in kdeconnect-kde after changing it.

## Protocol compatibility

The protocol has a version number (`1`), exchanged in the `hello` and `welcome` messages. Clients
disconnect from a server with a different version. Changes that existing clients would not
understand need a new protocol version. See [docs/protocol.md](docs/protocol.md).

## License

GNU AGPL v3 or later, see [LICENSES/AGPL-3.0-or-later.txt](LICENSES/AGPL-3.0-or-later.txt). If you
run a modified version as a service for others, section 13 of the AGPL requires you to offer its
users the modified source code. Test certificates in `tests/data/` are CC0-1.0.

The code was split out of
[meatybot/kdeconnect-kde](https://github.com/meatybot/kdeconnect-kde) with its history.
