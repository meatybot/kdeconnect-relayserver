#!/bin/sh
# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

# Uses /data/relay.crt and /data/relay.key, generating them on first start, so the
# certificate stays stable across restarts as long as /data is a persistent volume.
# Extra arguments are passed to kdeconnect-relayserver, for example --verbose.
set -eu

cert=/data/relay.crt
key=/data/relay.key

if [ ! -s "$cert" ] || [ ! -s "$key" ]; then
    echo "Generating a certificate in /data"
    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -subj "/CN=kdeconnect-relay" -keyout "$key" -out "$cert" 2>/dev/null
fi

exec /usr/bin/kdeconnect-relayserver --cert "$cert" --key "$key" "$@"
