# kdeconnect-relayserver

A small rendezvous relay that lets KDE Connect devices on different networks reach each other.
It only depends on QtCore and QtNetwork. The protocol is described in `docs/specs/relay.md`.

The relay never sees device traffic in the clear: devices run their normal TLS session end to end
through the relay and pin each other's certificates, then pair with the usual verification key.
The relay can see which devices are online, who connects to whom and how much data flows.

## Building

The server is built with the rest of KDE Connect unless `-DBUILD_RELAY_SERVER=OFF` is passed.
It produces a single `kdeconnect-relayserver` binary.

## Running

The server needs a TLS certificate and key. Devices do not verify it (see the spec), but keep it
stable so clients that pin it in the future keep working:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=kdeconnect-relay" -keyout relay.key -out relay.crt
kdeconnect-relayserver --cert relay.crt --key relay.key --port 1765
```

Open TCP port 1765 (or the port you chose) in your firewall. All state is kept in memory: a
restart disconnects every device, and devices reconnect on their own.

Options (defaults in parentheses):

- `--listen <address>`: address to bind (any)
- `--port <port>`: TCP port (1765)
- `--max-devices <n>`: registered devices (10000)
- `--max-connections-per-ip <n>`: concurrent connections per source IP (64)
- `--max-new-connections-per-ip <n>`: new connections per source IP and minute (30)
- `--max-tunnels-per-device <n>`: pending and active tunnels per device (16)
- `--tunnel-idle-timeout <seconds>`: close tunnels without traffic (600)
- `--verbose`: log registrations and tunnels, including relay keys

## systemd

`kdeconnect-relayserver.service` is an example unit running the server as a dynamic user with a
read-only view of the system. Put the certificate and key in `/etc/kdeconnect-relayserver/`,
readable by the service (the unit loads them as credentials), then:

```sh
sudo cp kdeconnect-relayserver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kdeconnect-relayserver
```

## Using it

On every device, set the relay server address (`host:port`) in the KDE Connect settings, or run
`kdeconnect-cli --relay-server host:port`. Each device then shows its relay key, for example
`ULJO-GBWQ-G4X3-LFX5-N5SH`. Enter that key (or the device's certificate fingerprint) on the other
device under "Connect to device" (`kdeconnect-cli --connect <key>`), then accept the pairing
request and compare the verification key on both screens. Paired devices reconnect through the
relay automatically when both are online.
