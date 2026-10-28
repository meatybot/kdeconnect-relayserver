# SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
# SPDX-License-Identifier: AGPL-3.0-or-later

FROM debian:trixie-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake ninja-build g++ qt6-base-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_TESTING=OFF -DINSTALL_SYSTEMD_UNIT=OFF \
    && cmake --build /build \
    && DESTDIR=/out cmake --install /build --strip

FROM debian:trixie-slim
# libqt6network6 pulls in libqt6core6t64 and OpenSSL. openssl generates a certificate on first start.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libqt6network6 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 1765 --home-dir /data --shell /usr/sbin/nologin relay \
    && mkdir -p /data && chown relay:relay /data
COPY --from=build /out/usr/bin/kdeconnect-relayserver /usr/bin/kdeconnect-relayserver
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV LANG=C.UTF-8
USER relay
VOLUME /data
EXPOSE 1765/tcp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
