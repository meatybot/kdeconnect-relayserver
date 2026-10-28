/**
 * SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RELAYSERVER_H
#define RELAYSERVER_H

#include <QHash>
#include <QHostAddress>
#include <QJsonObject>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>

struct RelayServerLimits {
    int maxDevices = 10000;
    int maxConnectionsPerIp = 64;
    int maxNewConnectionsPerIpPerMinute = 30;
    int maxTunnelsPerDevice = 16;
    int connectBurst = 20;
    int connectRefillMs = 3000;
    int maxWatched = 256;
    int handshakeTimeoutMs = 10000;
    int controlIdleTimeoutMs = 180000;
    int tokenExpiryMs = 30000;
    int tunnelIdleTimeoutMs = 600000;
    int preSpliceBufferSize = 64 * 1024;
    int forwardBufferSize = 1024 * 1024;
};

// Rendezvous relay for KDE Connect, see docs/protocol.md
class RelayServer : public QTcpServer
{
    Q_OBJECT

public:
    RelayServer(const QSslCertificate &certificate, const QSslKey &privateKey, const RelayServerLimits &limits = {}, QObject *parent = nullptr);
    ~RelayServer() override;

    int deviceCount() const
    {
        return m_controlsByFingerprint.size();
    }
    int tunnelCount() const
    {
        return m_tunnels.size();
    }
    void setVerbose(bool verbose)
    {
        m_verbose = verbose;
    }

Q_SIGNALS:
    void tunnelSpliced();

protected:
    void incomingConnection(qintptr socketDescriptor) override;

private:
    struct Control;
    struct Tunnel;

    void classify(QSslSocket *socket);
    void startControl(QSslSocket *socket);
    void registerControl(QSslSocket *socket);
    void removeControl(Control *control);
    void controlReadyRead(Control *control);
    void handleConnect(Control *control, const QJsonObject &message);
    void handleWatch(Control *control, const QJsonObject &message);
    void sendError(QSslSocket *socket, const QString &code, const QString &message, const QString &requestId = QString());

    void attach(QSslSocket *socket, const QJsonObject &message);
    void splice(Tunnel *tunnel);
    void pump(Tunnel *tunnel, QSslSocket *from, QSslSocket *to);
    void tunnelSocketGone(const QByteArray &token, QSslSocket *socket);
    void destroyTunnel(Tunnel *tunnel, bool graceful);

    bool rateLimitIp(const QHostAddress &address);

    const QSslCertificate m_certificate;
    const QSslKey m_privateKey;
    const RelayServerLimits m_limits;
    bool m_verbose = false;

    QHash<QString, Control *> m_controlsByFingerprint;
    QHash<QString, Control *> m_controlsByKey;
    QHash<QSslSocket *, Control *> m_controlsBySocket;
    QHash<QByteArray, Tunnel *> m_tunnels;
    QHash<QHostAddress, int> m_connectionsPerIp;
    QHash<QHostAddress, QList<qint64>> m_recentConnectionsPerIp;
};

#endif
