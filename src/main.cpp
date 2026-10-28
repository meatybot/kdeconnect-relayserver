/**
 * SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFile>
#include <QSslKey>

#include "core/backends/relay/relayprotocol.h"
#include "relayserver.h"

static QSslKey loadKey(const QByteArray &data)
{
    for (QSsl::KeyAlgorithm algorithm : {QSsl::Ec, QSsl::Rsa}) {
        QSslKey key(data, algorithm, QSsl::Pem, QSsl::PrivateKey);
        if (!key.isNull()) {
            return key;
        }
    }
    return {};
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("kdeconnect-relayserver"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Relay server for KDE Connect devices on different networks"));
    parser.addHelpOption();

    const RelayServerLimits defaults;
    QCommandLineOption listenOption(QStringLiteral("listen"), QStringLiteral("Address to listen on (default: any)."), QStringLiteral("address"));
    QCommandLineOption portOption(QStringLiteral("port"),
                                  QStringLiteral("TCP port (default: %1).").arg(RelayProtocol::DefaultPort),
                                  QStringLiteral("port"),
                                  QString::number(RelayProtocol::DefaultPort));
    QCommandLineOption certOption(QStringLiteral("cert"), QStringLiteral("PEM certificate of the server (required)."), QStringLiteral("file"));
    QCommandLineOption keyOption(QStringLiteral("key"), QStringLiteral("PEM private key of the server (required)."), QStringLiteral("file"));
    QCommandLineOption maxDevicesOption(QStringLiteral("max-devices"),
                                        QStringLiteral("Maximum registered devices."),
                                        QStringLiteral("n"),
                                        QString::number(defaults.maxDevices));
    QCommandLineOption maxPerIpOption(QStringLiteral("max-connections-per-ip"),
                                      QStringLiteral("Maximum concurrent connections per source IP."),
                                      QStringLiteral("n"),
                                      QString::number(defaults.maxConnectionsPerIp));
    QCommandLineOption ratePerIpOption(QStringLiteral("max-new-connections-per-ip"),
                                       QStringLiteral("Maximum new connections per source IP per minute."),
                                       QStringLiteral("n"),
                                       QString::number(defaults.maxNewConnectionsPerIpPerMinute));
    QCommandLineOption maxTunnelsOption(QStringLiteral("max-tunnels-per-device"),
                                        QStringLiteral("Maximum pending and active tunnels per device."),
                                        QStringLiteral("n"),
                                        QString::number(defaults.maxTunnelsPerDevice));
    QCommandLineOption tunnelIdleOption(QStringLiteral("tunnel-idle-timeout"),
                                        QStringLiteral("Seconds without traffic before a tunnel is closed."),
                                        QStringLiteral("seconds"),
                                        QString::number(defaults.tunnelIdleTimeoutMs / 1000));
    QCommandLineOption verboseOption(QStringLiteral("verbose"), QStringLiteral("Log registrations and tunnels."));
    parser.addOptions({listenOption,
                       portOption,
                       certOption,
                       keyOption,
                       maxDevicesOption,
                       maxPerIpOption,
                       ratePerIpOption,
                       maxTunnelsOption,
                       tunnelIdleOption,
                       verboseOption});
    parser.process(app);

    if (!parser.isSet(certOption) || !parser.isSet(keyOption)) {
        qCritical("--cert and --key are required");
        return 1;
    }

    QFile certFile(parser.value(certOption));
    QFile keyFile(parser.value(keyOption));
    if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) {
        qCritical("Cannot read the certificate or key file");
        return 1;
    }
    const QList<QSslCertificate> certificates = QSslCertificate::fromData(certFile.readAll(), QSsl::Pem);
    const QSslKey key = loadKey(keyFile.readAll());
    if (certificates.isEmpty() || key.isNull()) {
        qCritical("Invalid certificate or key");
        return 1;
    }

    auto positive = [&parser](const QCommandLineOption &option, int *out) {
        bool ok = false;
        const int value = parser.value(option).toInt(&ok);
        if (!ok || value <= 0) {
            qCritical("Invalid value for --%s", qPrintable(option.names().constFirst()));
            return false;
        }
        *out = value;
        return true;
    };

    RelayServerLimits limits;
    int port = 0;
    int tunnelIdleSeconds = 0;
    if (!positive(portOption, &port) || port > 65535 || !positive(maxDevicesOption, &limits.maxDevices)
        || !positive(maxPerIpOption, &limits.maxConnectionsPerIp) || !positive(ratePerIpOption, &limits.maxNewConnectionsPerIpPerMinute)
        || !positive(maxTunnelsOption, &limits.maxTunnelsPerDevice) || !positive(tunnelIdleOption, &tunnelIdleSeconds)) {
        return 1;
    }
    limits.tunnelIdleTimeoutMs = tunnelIdleSeconds * 1000;

    QHostAddress address = QHostAddress::Any;
    if (parser.isSet(listenOption) && !address.setAddress(parser.value(listenOption))) {
        qCritical("Invalid listen address");
        return 1;
    }

    RelayServer server(certificates.constFirst(), key, limits);
    server.setVerbose(parser.isSet(verboseOption));
    if (!server.listen(address, static_cast<quint16>(port))) {
        qCritical("Cannot listen: %s", qPrintable(server.errorString()));
        return 1;
    }
    qInfo("Listening on %s:%d", qPrintable(address.toString()), port);

    return app.exec();
}
