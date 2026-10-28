/**
 * SPDX-FileCopyrightText: 2026 KDE Connect contributors
 *
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
 */

#include "relayserver.h"

#include <QDateTime>
#include <QJsonArray>
#include <QPointer>
#include <QRandomGenerator>
#include <QSet>
#include <QSslConfiguration>
#include <QTimer>

#include "core/backends/relay/relayprotocol.h"

struct RelayServer::Control {
    QSslSocket *socket = nullptr;
    QString fingerprint;
    QString key;
    QSet<QString> watched;
    QTimer idleTimer;
    double connectTokens = 0;
    qint64 lastRefill = 0;
};

struct RelayServer::Tunnel {
    QByteArray token;
    QString initiator; // fingerprints, used for the per-device tunnel limit
    QString target;
    QPointer<QSslSocket> first;
    QPointer<QSslSocket> second;
    QByteArray pending; // bytes from the first side before the second attached
    bool spliced = false;
    QTimer timer; // token expiry before splicing, idle timeout after
};

RelayServer::RelayServer(const QSslCertificate &certificate, const QSslKey &privateKey, const RelayServerLimits &limits, QObject *parent)
    : QTcpServer(parent)
    , m_certificate(certificate)
    , m_privateKey(privateKey)
    , m_limits(limits)
{
}

RelayServer::~RelayServer()
{
    close();
    const auto tunnels = m_tunnels.values();
    m_tunnels.clear();
    qDeleteAll(tunnels);
    const auto controls = m_controlsBySocket.values();
    m_controlsBySocket.clear();
    m_controlsByFingerprint.clear();
    m_controlsByKey.clear();
    qDeleteAll(controls);
    const auto sockets = findChildren<QSslSocket *>(Qt::FindDirectChildrenOnly);
    for (QSslSocket *socket : sockets) {
        disconnect(socket, nullptr, this, nullptr);
        delete socket;
    }
}

bool RelayServer::rateLimitIp(const QHostAddress &rawAddress)
{
    bool isIPv4;
    const quint32 ipv4 = rawAddress.toIPv4Address(&isIPv4);
    const QHostAddress address = isIPv4 ? QHostAddress(ipv4) : rawAddress;

    if (m_connectionsPerIp.value(address) >= m_limits.maxConnectionsPerIp) {
        return true;
    }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QList<qint64> &recent = m_recentConnectionsPerIp[address];
    recent.removeIf([now](qint64 t) {
        return t + 60000 <= now;
    });
    if (recent.size() >= m_limits.maxNewConnectionsPerIpPerMinute) {
        return true;
    }
    if (m_recentConnectionsPerIp.size() > 4096) {
        m_recentConnectionsPerIp.removeIf([now](const auto &it) {
            return it.value().isEmpty() || it.value().last() + 60000 <= now;
        });
    }
    recent.append(now);
    return false;
}

void RelayServer::incomingConnection(qintptr socketDescriptor)
{
    QSslSocket *socket = new QSslSocket(this);
    if (!socket->setSocketDescriptor(socketDescriptor)) {
        delete socket;
        return;
    }

    bool isIPv4;
    const quint32 ipv4 = socket->peerAddress().toIPv4Address(&isIPv4);
    const QHostAddress address = isIPv4 ? QHostAddress(ipv4) : socket->peerAddress();
    if (rateLimitIp(address)) {
        if (m_verbose) {
            qInfo() << "Rate limited connection from" << address;
        }
        socket->abort();
        socket->deleteLater();
        return;
    }
    m_connectionsPerIp[address]++;
    connect(socket, &QObject::destroyed, this, [this, address]() {
        auto it = m_connectionsPerIp.find(address);
        if (it != m_connectionsPerIp.end() && --it.value() <= 0) {
            m_connectionsPerIp.erase(it);
        }
    });
    connect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);

    // Abort connections that don't register or attach in time. Deleted once the socket is classified and set up.
    QTimer *handshakeTimer = new QTimer(socket);
    handshakeTimer->setObjectName(QStringLiteral("handshakeTimer"));
    handshakeTimer->setSingleShot(true);
    connect(handshakeTimer, &QTimer::timeout, socket, &QAbstractSocket::abort);
    handshakeTimer->start(m_limits.handshakeTimeoutMs);

    connect(socket, &QIODevice::readyRead, this, [this, socket]() {
        classify(socket);
    });
}

void RelayServer::classify(QSslSocket *socket)
{
    if (!socket->canReadLine()) {
        if (socket->bytesAvailable() > RelayProtocol::MaxLineSize) {
            socket->abort();
        }
        return;
    }
    disconnect(socket, &QIODevice::readyRead, this, nullptr);

    QJsonObject message;
    const QByteArray line = socket->readLine(RelayProtocol::MaxLineSize + 1);
    if (!line.endsWith('\n') || !RelayProtocol::decode(line, &message)) {
        socket->abort();
        return;
    }
    const QString type = message.value(QLatin1String("type")).toString();
    if (type == QLatin1String("hello")) {
        // The client waits for "starttls" before sending its ClientHello, so nothing else may be buffered
        if (socket->bytesAvailable() > 0 || message.value(QLatin1String("version")).toInt() != RelayProtocol::Version) {
            socket->abort();
            return;
        }
        socket->write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("starttls")}}));
        socket->flush();
        startControl(socket);
    } else if (type == QLatin1String("attach")) {
        attach(socket, message);
    } else {
        socket->abort();
    }
}

void RelayServer::startControl(QSslSocket *socket)
{
    QSslConfiguration config = QSslConfiguration::defaultConfiguration();
    config.setLocalCertificate(m_certificate);
    config.setPrivateKey(m_privateKey);
    config.setPeerVerifyMode(QSslSocket::QueryPeer);
    socket->setSslConfiguration(config);
    connect(socket, &QSslSocket::sslErrors, socket, [socket](const QList<QSslError> &) {
        // Client certificates are self-signed by design: they are identified, not verified
        socket->ignoreSslErrors();
    });
    connect(socket, &QSslSocket::encrypted, this, [this, socket]() {
        registerControl(socket);
    });
    socket->startServerEncryption();
}

void RelayServer::registerControl(QSslSocket *socket)
{
    if (QTimer *t = socket->findChild<QTimer *>(QStringLiteral("handshakeTimer"))) {
        delete t;
    }
    const QSslCertificate peer = socket->peerCertificate();
    if (peer.isNull()) {
        sendError(socket, QStringLiteral("bad_request"), QStringLiteral("A client certificate is required"));
        socket->disconnectFromHost();
        return;
    }
    const QString fingerprint = RelayProtocol::fingerprint(peer);
    const QString key = RelayProtocol::relayKey(peer);

    if (Control *old = m_controlsByFingerprint.value(fingerprint)) {
        sendError(old->socket, QStringLiteral("replaced"), QStringLiteral("Another connection registered with the same certificate"));
        QSslSocket *oldSocket = old->socket;
        removeControl(old);
        oldSocket->disconnectFromHost();
    } else if (m_controlsByKey.contains(key)) {
        sendError(socket, QStringLiteral("bad_request"), QStringLiteral("Relay key collision"));
        socket->disconnectFromHost();
        return;
    } else if (m_controlsByFingerprint.size() >= m_limits.maxDevices) {
        sendError(socket, QStringLiteral("server_full"), QStringLiteral("Too many devices"));
        socket->disconnectFromHost();
        return;
    }

    Control *control = new Control;
    control->socket = socket;
    control->fingerprint = fingerprint;
    control->key = key;
    control->connectTokens = m_limits.connectBurst;
    control->lastRefill = QDateTime::currentMSecsSinceEpoch();
    control->idleTimer.setSingleShot(true);
    control->idleTimer.setInterval(m_limits.controlIdleTimeoutMs);
    connect(&control->idleTimer, &QTimer::timeout, socket, &QAbstractSocket::abort);
    control->idleTimer.start();

    m_controlsByFingerprint.insert(fingerprint, control);
    m_controlsByKey.insert(key, control);
    m_controlsBySocket.insert(socket, control);

    connect(socket, &QIODevice::readyRead, this, [this, socket]() {
        if (Control *c = m_controlsBySocket.value(socket)) {
            controlReadyRead(c);
        }
    });
    connect(socket, &QObject::destroyed, this, [this, socket]() {
        if (Control *c = m_controlsBySocket.value(socket)) {
            removeControl(c);
        }
    });

    if (m_verbose) {
        qInfo() << "Registered" << key;
    }

    QJsonObject welcome{
        {QStringLiteral("type"), QStringLiteral("welcome")},
        {QStringLiteral("version"), RelayProtocol::Version},
        {QStringLiteral("key"), key},
        {QStringLiteral("fingerprint"), fingerprint},
    };
    socket->write(RelayProtocol::encode(welcome));

    if (socket->bytesAvailable()) {
        controlReadyRead(control);
    }
}

void RelayServer::removeControl(Control *control)
{
    m_controlsBySocket.remove(control->socket);
    if (m_controlsByFingerprint.value(control->fingerprint) == control) {
        m_controlsByFingerprint.remove(control->fingerprint);
    }
    if (m_controlsByKey.value(control->key) == control) {
        m_controlsByKey.remove(control->key);
    }
    delete control;
}

void RelayServer::sendError(QSslSocket *socket, const QString &code, const QString &message, const QString &requestId)
{
    QJsonObject error{
        {QStringLiteral("type"), QStringLiteral("error")},
        {QStringLiteral("code"), code},
        {QStringLiteral("message"), message},
    };
    if (!requestId.isEmpty()) {
        error.insert(QStringLiteral("requestId"), requestId);
    }
    socket->write(RelayProtocol::encode(error));
}

void RelayServer::controlReadyRead(Control *control)
{
    QSslSocket *socket = control->socket;
    while (m_controlsBySocket.contains(socket) && socket->canReadLine()) {
        const QByteArray line = socket->readLine(RelayProtocol::MaxLineSize + 1);
        control->idleTimer.start();
        QJsonObject message;
        if (!line.endsWith('\n') || !RelayProtocol::decode(line, &message)) {
            sendError(socket, QStringLiteral("bad_request"), QStringLiteral("Malformed message"));
            socket->disconnectFromHost();
            return;
        }
        const QString type = message.value(QLatin1String("type")).toString();
        if (type == QLatin1String("connect")) {
            handleConnect(control, message);
        } else if (type == QLatin1String("watch")) {
            handleWatch(control, message);
        } else if (type == QLatin1String("ping")) {
            socket->write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("pong")}}));
        } else {
            sendError(socket, QStringLiteral("bad_request"), QStringLiteral("Unknown message type"));
        }
    }
    if (m_controlsBySocket.contains(socket) && !socket->canReadLine() && socket->bytesAvailable() > RelayProtocol::MaxLineSize) {
        sendError(socket, QStringLiteral("bad_request"), QStringLiteral("Line too long"));
        socket->disconnectFromHost();
    }
}

void RelayServer::handleConnect(Control *control, const QJsonObject &message)
{
    const QString requestId = message.value(QLatin1String("requestId")).toString().left(32);
    const QString purpose = message.value(QLatin1String("purpose")).toString();
    const RelayProtocol::Target target = RelayProtocol::parseTarget(message.value(QLatin1String("target")).toString());

    if (!target.isValid() || (purpose != QLatin1String("link") && purpose != QLatin1String("payload"))) {
        sendError(control->socket, QStringLiteral("bad_request"), QStringLiteral("Invalid target or purpose"), requestId);
        return;
    }

    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    control->connectTokens = qMin<double>(m_limits.connectBurst, control->connectTokens + double(now - control->lastRefill) / m_limits.connectRefillMs);
    control->lastRefill = now;
    if (control->connectTokens < 1) {
        sendError(control->socket, QStringLiteral("rate_limited"), QStringLiteral("Too many connect requests"), requestId);
        return;
    }
    control->connectTokens -= 1;

    Control *peer = target.kind == RelayProtocol::Target::Key ? m_controlsByKey.value(target.value) : m_controlsByFingerprint.value(target.value);
    if (!peer) {
        sendError(control->socket, QStringLiteral("not_found"), QStringLiteral("No such device online"), requestId);
        return;
    }
    if (peer == control) {
        sendError(control->socket, QStringLiteral("self"), QStringLiteral("Cannot connect to yourself"), requestId);
        return;
    }

    int initiatorTunnels = 0;
    int peerTunnels = 0;
    for (const Tunnel *tunnel : std::as_const(m_tunnels)) {
        if (tunnel->initiator == control->fingerprint || tunnel->target == control->fingerprint) {
            initiatorTunnels++;
        }
        if (tunnel->initiator == peer->fingerprint || tunnel->target == peer->fingerprint) {
            peerTunnels++;
        }
    }
    if (initiatorTunnels >= m_limits.maxTunnelsPerDevice || peerTunnels >= m_limits.maxTunnelsPerDevice) {
        sendError(control->socket, QStringLiteral("too_many_tunnels"), QStringLiteral("Too many tunnels"), requestId);
        return;
    }

    QByteArray random(16, Qt::Uninitialized);
    QRandomGenerator::system()->fillRange(reinterpret_cast<quint32 *>(random.data()), random.size() / int(sizeof(quint32)));
    const QByteArray token = random.toHex();

    Tunnel *tunnel = new Tunnel;
    tunnel->token = token;
    tunnel->initiator = control->fingerprint;
    tunnel->target = peer->fingerprint;
    tunnel->timer.setSingleShot(true);
    connect(&tunnel->timer, &QTimer::timeout, this, [this, token]() {
        if (Tunnel *t = m_tunnels.value(token)) {
            if (m_verbose) {
                qInfo() << (t->spliced ? "Tunnel idle timeout" : "Tunnel token expired");
            }
            destroyTunnel(t, false);
        }
    });
    tunnel->timer.start(m_limits.tokenExpiryMs);
    m_tunnels.insert(token, tunnel);

    QJsonObject reply{
        {QStringLiteral("type"), QStringLiteral("tunnel")},
        {QStringLiteral("token"), QString::fromLatin1(token)},
        {QStringLiteral("purpose"), purpose},
        {QStringLiteral("peerKey"), peer->key},
        {QStringLiteral("peerFingerprint"), peer->fingerprint},
    };
    if (!requestId.isEmpty()) {
        reply.insert(QStringLiteral("requestId"), requestId);
    }
    control->socket->write(RelayProtocol::encode(reply));

    if (purpose == QLatin1String("link")) {
        QJsonObject incoming{
            {QStringLiteral("type"), QStringLiteral("incoming")},
            {QStringLiteral("token"), QString::fromLatin1(token)},
            {QStringLiteral("peerKey"), control->key},
            {QStringLiteral("peerFingerprint"), control->fingerprint},
        };
        peer->socket->write(RelayProtocol::encode(incoming));
    }
}

void RelayServer::handleWatch(Control *control, const QJsonObject &message)
{
    const QJsonArray list = message.value(QLatin1String("fingerprints")).toArray();
    if (list.size() > m_limits.maxWatched) {
        sendError(control->socket, QStringLiteral("bad_request"), QStringLiteral("Too many watched fingerprints"));
        return;
    }
    control->watched.clear();
    for (const QJsonValue &value : list) {
        const RelayProtocol::Target target = RelayProtocol::parseTarget(value.toString());
        if (target.kind == RelayProtocol::Target::Fingerprint) {
            control->watched.insert(target.value);
        }
    }
    // Only tell devices about each other when both watch each other
    for (const QString &fingerprint : std::as_const(control->watched)) {
        Control *peer = m_controlsByFingerprint.value(fingerprint);
        if (!peer || peer == control || !peer->watched.contains(control->fingerprint)) {
            continue;
        }
        control->socket->write(RelayProtocol::encode({
            {QStringLiteral("type"), QStringLiteral("peer_online")},
            {QStringLiteral("peerKey"), peer->key},
            {QStringLiteral("peerFingerprint"), peer->fingerprint},
        }));
        peer->socket->write(RelayProtocol::encode({
            {QStringLiteral("type"), QStringLiteral("peer_online")},
            {QStringLiteral("peerKey"), control->key},
            {QStringLiteral("peerFingerprint"), control->fingerprint},
        }));
    }
}

void RelayServer::attach(QSslSocket *socket, const QJsonObject &message)
{
    const QByteArray token = message.value(QLatin1String("token")).toString().toLatin1();
    Tunnel *tunnel = m_tunnels.value(token);
    if (!tunnel || tunnel->spliced || (tunnel->first && tunnel->second)) {
        if (m_verbose) {
            qInfo() << "Attach with an unknown or used token";
        }
        socket->abort();
        return;
    }

    if (QTimer *t = socket->findChild<QTimer *>(QStringLiteral("handshakeTimer"))) {
        delete t;
    }
    socket->setReadBufferSize(m_limits.forwardBufferSize);
    connect(socket, &QAbstractSocket::disconnected, this, [this, token, socket]() {
        tunnelSocketGone(token, socket);
    });

    if (!tunnel->first) {
        tunnel->first = socket;
        tunnel->pending = socket->readAll();
        connect(socket, &QIODevice::readyRead, this, [this, token, socket]() {
            Tunnel *t = m_tunnels.value(token);
            if (!t || t->spliced) {
                return;
            }
            t->pending += socket->readAll();
            if (t->pending.size() > m_limits.preSpliceBufferSize) {
                destroyTunnel(t, false);
            }
        });
        if (tunnel->pending.size() > m_limits.preSpliceBufferSize) {
            destroyTunnel(tunnel, false);
        }
        return;
    }

    tunnel->second = socket;
    splice(tunnel);
}

void RelayServer::splice(Tunnel *tunnel)
{
    QSslSocket *a = tunnel->first;
    QSslSocket *b = tunnel->second;
    disconnect(a, &QIODevice::readyRead, this, nullptr);
    tunnel->spliced = true;
    tunnel->timer.start(m_limits.tunnelIdleTimeoutMs);

    if (!tunnel->pending.isEmpty()) {
        b->write(tunnel->pending);
        tunnel->pending.clear();
    }

    const QByteArray token = tunnel->token;
    auto pumpBoth = [this, token]() {
        Tunnel *t = m_tunnels.value(token);
        if (!t || !t->first || !t->second) {
            return;
        }
        pump(t, t->first, t->second);
        if ((t = m_tunnels.value(token)) && t->first && t->second) {
            pump(t, t->second, t->first);
        }
    };
    connect(a, &QIODevice::readyRead, this, pumpBoth);
    connect(b, &QIODevice::readyRead, this, pumpBoth);
    connect(a, &QIODevice::bytesWritten, this, pumpBoth);
    connect(b, &QIODevice::bytesWritten, this, pumpBoth);

    if (m_verbose) {
        qInfo() << "Tunnel spliced";
    }
    Q_EMIT tunnelSpliced();
    pumpBoth();
}

void RelayServer::pump(Tunnel *tunnel, QSslSocket *from, QSslSocket *to)
{
    bool moved = false;
    while (from->bytesAvailable() > 0 && to->bytesToWrite() < m_limits.forwardBufferSize) {
        const QByteArray chunk = from->read(qMin<qint64>(from->bytesAvailable(), 64 * 1024));
        if (chunk.isEmpty()) {
            break;
        }
        to->write(chunk);
        moved = true;
    }
    if (moved) {
        tunnel->timer.start(m_limits.tunnelIdleTimeoutMs);
    }
}

void RelayServer::tunnelSocketGone(const QByteArray &token, QSslSocket *socket)
{
    Tunnel *tunnel = m_tunnels.value(token);
    if (!tunnel) {
        return;
    }
    if (tunnel->spliced) {
        // Forward what is still buffered before closing the other side
        QSslSocket *other = (socket == tunnel->first) ? tunnel->second.data() : tunnel->first.data();
        if (other && socket->bytesAvailable()) {
            other->write(socket->readAll());
        }
        destroyTunnel(tunnel, true);
    } else {
        destroyTunnel(tunnel, false);
    }
}

void RelayServer::destroyTunnel(Tunnel *tunnel, bool graceful)
{
    m_tunnels.remove(tunnel->token);
    for (QSslSocket *socket : {tunnel->first.data(), tunnel->second.data()}) {
        if (!socket) {
            continue;
        }
        // Keep the destroyed() connection, it maintains the per-IP connection count
        disconnect(socket, &QIODevice::readyRead, this, nullptr);
        disconnect(socket, &QIODevice::bytesWritten, this, nullptr);
        disconnect(socket, &QAbstractSocket::disconnected, this, nullptr);
        if (graceful) {
            socket->disconnectFromHost();
        } else {
            socket->abort();
        }
    }
    delete tunnel;
}

#include "moc_relayserver.cpp"
