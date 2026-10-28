<!--
SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Hosting a relay

A relay needs a machine with a public IP address or a forwarded port, one open TCP port (1765 by
default) and a TLS certificate. It keeps all state in memory, so it needs no database and no
backups beyond its certificate.

## What the relay sees

Device traffic is end-to-end encrypted between the devices. The relay cannot read it or change it.
It does see metadata:

- which relay keys and certificate fingerprints are online, and from which IP address
- which device connects to which, and when
- how many bytes each tunnel carries

With `--verbose` the server logs registrations and tunnels including relay keys. Without it, the
server logs only startup and errors. Choose a log retention that matches what you promise your
users.

## Sizing

Every relayed byte passes through the server, so bandwidth is the limit that matters. File
transfers and audio streams between two relayed devices use the upload and download bandwidth of
the relay at the same time. Control connections are cheap: an idle registered device sends one
`ping` per minute.

The default limits (see `kdeconnect-relayserver --help`) allow 10000 registered devices and 16
tunnels per device. Each spliced tunnel buffers at most 1 MiB per direction. Raise `ulimit -n`
(the systemd unit sets `LimitNOFILE=65536`) when you expect more than about 1000 devices, because
every device holds one socket and every tunnel holds two.

## The certificate

Clients do not verify the relay certificate in protocol version 1, so a self-signed certificate
is enough. Keep it stable anyway: a later protocol version may let clients pin it.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=kdeconnect-relay" -keyout relay.key -out relay.crt
```

A certificate from a public CA, for example one issued by Let's Encrypt for the relay's host
name, also works. Restart the server after renewing it, because it reads the files only at startup.

## Option 1: container

Images are published to `ghcr.io/meatybot/kdeconnect-relayserver` for amd64 and arm64. The image
runs as an unprivileged user, generates a certificate in `/data` on first start and reuses it
afterwards. Keep `/data` on a persistent volume.

```sh
docker run -d --name kdeconnect-relay --restart unless-stopped \
    -p 1765:1765 -v kdeconnect-relay:/data \
    ghcr.io/meatybot/kdeconnect-relayserver:latest
```

Arguments after the image name are passed to the server, for example `--verbose` or
`--max-devices 500`. To use your own certificate, put `relay.crt` and `relay.key` into the volume
before the first start. The files must be readable by uid 1765.

Docker Compose:

```yaml
services:
  relay:
    image: ghcr.io/meatybot/kdeconnect-relayserver:latest
    restart: unless-stopped
    ports:
      - "1765:1765"
    volumes:
      - relay-data:/data
volumes:
  relay-data:
```

## Option 2: systemd on a Linux host

Download `kdeconnect-relayserver-<version>-linux-x86_64` (or `-aarch64`) from the
[releases page](https://github.com/meatybot/kdeconnect-relayserver/releases) and install it, or
build from source (see the README). The binaries are linked dynamically against Qt 6: install
your distribution's Qt 6 network library first (`libqt6network6` on Debian and Ubuntu,
`qt6-base` on Arch and Fedora).

```sh
sudo install -m 755 kdeconnect-relayserver-*-linux-x86_64 /usr/local/bin/kdeconnect-relayserver
sudo mkdir -p /etc/kdeconnect-relayserver
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=kdeconnect-relay" -keyout /etc/kdeconnect-relayserver/relay.key \
    -out /etc/kdeconnect-relayserver/relay.crt
sudo chmod 600 /etc/kdeconnect-relayserver/relay.key
```

The release also contains `kdeconnect-relayserver.service`, built for `/usr/bin`. With the binary
in `/usr/local/bin`, change `ExecStart` accordingly, then install it:

```sh
sudo sed -i 's|/usr/bin/|/usr/local/bin/|' kdeconnect-relayserver.service
sudo cp kdeconnect-relayserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kdeconnect-relayserver
journalctl -u kdeconnect-relayserver
```

The unit runs the server as a transient user (`DynamicUser=yes`) with a read-only view of the
system. systemd passes the certificate and key in as credentials, so they can stay readable by
root only. Edit `ExecStart` with `systemctl edit kdeconnect-relayserver` to change the port or
limits.

## Firewall

Allow inbound TCP on the relay port, for example:

```sh
sudo ufw allow 1765/tcp
# or
sudo firewall-cmd --permanent --add-port=1765/tcp && sudo firewall-cmd --reload
```

The relay speaks a custom protocol that starts in plain text and switches to TLS. It cannot run
behind an HTTP reverse proxy. A TCP (layer 4) proxy such as HAProxy in `mode tcp` or nginx
`stream` works, but the per-IP limits then see the proxy's address. Disable them by raising
`--max-connections-per-ip` and `--max-new-connections-per-ip`, or skip the proxy.

## Checking that it works

From any machine:

```sh
printf '{"type":"hello","version":1}\n' | timeout 3 nc relay.example.org 1765
```

prints `{"type":"starttls"}` when the relay is reachable. Then, on two devices, set the relay
address (`kdeconnect-cli --relay-server relay.example.org:1765` on the desktop, or Settings >
Relay server on Android). `kdeconnect-cli --relay-info` shows `registered` and the device's relay
key once the device is connected.

## Upgrading

Replace the binary or pull the new image and restart. Devices reconnect on their own within
seconds. Restarting drops active tunnels, so running file transfers fail and have to be repeated.

## Running a modified version

The relay is licensed under the GNU AGPL v3 or later. If you modify it and let others use your
relay, section 13 of the AGPL requires you to offer them the modified source code, for example
with a link next to the relay address you publish.
