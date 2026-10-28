/**
 * SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// Tests the server over real sockets with a minimal client written from docs/protocol.md,
// independent of the KDE Connect client classes.

#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QSignalSpy>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpSocket>
#include <QTest>

#include <memory>

#include "relayprotocol.h"
#include "relayserver.h"

using RelayProtocol::Target;

namespace
{
struct Identity {
    QSslCertificate certificate;
    QSslKey key;

    static Identity load(const QString &name)
    {
        Identity id;
        QFile crt(QFINDTESTDATA(QStringLiteral("data/%1.crt").arg(name)));
        QFile key(QFINDTESTDATA(QStringLiteral("data/%1.key").arg(name)));
        if (crt.open(QIODevice::ReadOnly) && key.open(QIODevice::ReadOnly)) {
            id.certificate = QSslCertificate(crt.readAll(), QSsl::Pem);
            const QByteArray pem = key.readAll();
            id.key = QSslKey(pem, QSsl::Ec, QSsl::Pem, QSsl::PrivateKey);
            if (id.key.isNull()) {
                id.key = QSslKey(pem, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
            }
        }
        return id;
    }
    QString fingerprint() const
    {
        return RelayProtocol::fingerprint(certificate);
    }
    QString relayKey() const
    {
        return RelayProtocol::relayKey(certificate);
    }
};

QSslConfiguration tlsConfig(const Identity &identity)
{
    QSslConfiguration config = QSslConfiguration::defaultConfiguration();
    config.setLocalCertificate(identity.certificate);
    config.setPrivateKey(identity.key);
    config.setPeerVerifyMode(QSslSocket::QueryPeer);
    return config;
}

QByteArray readLine(QIODevice *device, int timeoutMs = 5000)
{
    QElapsedTimer timer;
    timer.start();
    while (!device->canReadLine() && timer.elapsed() < timeoutMs) {
        QTest::qWait(5);
    }
    return device->readLine();
}

QByteArray readExactly(QIODevice *device, qint64 size, int timeoutMs = 20000)
{
    QByteArray result;
    QElapsedTimer timer;
    timer.start();
    while (result.size() < size && timer.elapsed() < timeoutMs) {
        result += device->read(size - result.size());
        if (result.size() < size) {
            QTest::qWait(5);
        }
    }
    return result;
}

QByteArray pattern(int size)
{
    QByteArray data(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i) {
        data[i] = char((i * 31 + 7) & 0xff);
    }
    return data;
}

// The server runs on this thread, so waits must spin the event loop instead of blocking
bool waitConnected(QAbstractSocket *socket, int timeoutMs = 5000)
{
    return QTest::qWaitFor(
        [socket]() {
            return socket->state() == QAbstractSocket::ConnectedState;
        },
        timeoutMs);
}

bool waitEncrypted(QSslSocket *socket, int timeoutMs = 5000)
{
    return QTest::qWaitFor(
        [socket]() {
            return socket->isEncrypted() || socket->state() == QAbstractSocket::UnconnectedState;
        },
        timeoutMs)
        && socket->isEncrypted();
}

bool waitClosed(QAbstractSocket *socket, int timeoutMs = 5000)
{
    QElapsedTimer timer;
    timer.start();
    while (socket->state() != QAbstractSocket::UnconnectedState && timer.elapsed() < timeoutMs) {
        QTest::qWait(5);
    }
    return socket->state() == QAbstractSocket::UnconnectedState;
}

// Control connection: hello, starttls, TLS with the device certificate, then JSON lines
class Control
{
public:
    Control(quint16 port, const Identity &identity)
        : m_identity(identity)
    {
        m_socket.setSslConfiguration(tlsConfig(identity));
        QObject::connect(&m_socket, &QSslSocket::sslErrors, &m_socket, [this](const QList<QSslError> &) {
            m_socket.ignoreSslErrors();
        });
        m_socket.connectToHost(QHostAddress::LocalHost, port);
        if (!waitConnected(&m_socket)) {
            return;
        }
        m_socket.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("version"), RelayProtocol::Version}}));
        if (next().value(QLatin1String("type")).toString() != QLatin1String("starttls")) {
            return;
        }
        m_socket.startClientEncryption();
        if (!waitEncrypted(&m_socket)) {
            return;
        }
        m_welcome = next();
    }

    bool registered() const
    {
        return m_welcome.value(QLatin1String("type")).toString() == QLatin1String("welcome");
    }
    QJsonObject welcome() const
    {
        return m_welcome;
    }

    void send(const QJsonObject &message)
    {
        m_socket.write(RelayProtocol::encode(message));
    }

    // Next message, or an empty object on timeout or disconnect
    QJsonObject next(int timeoutMs = 5000)
    {
        QJsonObject message;
        const QByteArray line = readLine(&m_socket, timeoutMs);
        if (line.isEmpty() || !RelayProtocol::decode(line, &message)) {
            return {};
        }
        return message;
    }

    QJsonObject connect(const Target &target, const QString &purpose = QStringLiteral("link"), const QString &requestId = QStringLiteral("1"))
    {
        send({{QStringLiteral("type"), QStringLiteral("connect")},
              {QStringLiteral("requestId"), requestId},
              {QStringLiteral("target"), target.value},
              {QStringLiteral("purpose"), purpose}});
        return next();
    }

    QString connectError(const Target &target, const QString &purpose = QStringLiteral("link"))
    {
        const QJsonObject reply = connect(target, purpose);
        const QString type = reply.value(QLatin1String("type")).toString();
        if (type == QLatin1String("tunnel")) {
            return QStringLiteral("ok");
        }
        if (type != QLatin1String("error") || reply.value(QLatin1String("requestId")).toString() != QLatin1String("1")) {
            return QStringLiteral("no reply");
        }
        return reply.value(QLatin1String("code")).toString();
    }

    void watch(const QStringList &fingerprints)
    {
        send({{QStringLiteral("type"), QStringLiteral("watch")}, {QStringLiteral("fingerprints"), QJsonArray::fromStringList(fingerprints)}});
    }

    QSslSocket *socket()
    {
        return &m_socket;
    }

private:
    Identity m_identity;
    QSslSocket m_socket;
    QJsonObject m_welcome;
};

// Data connection: attach line, then TLS end to end with the peer through the splice
class Data : public QSslSocket
{
public:
    enum Role {
        TlsServer,
        TlsClient,
    };

    Data(quint16 port, const QString &token, Role role, const Identity &identity)
    {
        setSslConfiguration(tlsConfig(identity));
        QObject::connect(this, &QSslSocket::sslErrors, this, [this](const QList<QSslError> &) {
            ignoreSslErrors();
        });
        QObject::connect(this, &QAbstractSocket::connected, this, [this, token, role]() {
            write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), token}}));
            if (role == TlsServer) {
                startServerEncryption();
            } else {
                startClientEncryption();
            }
        });
        connectToHost(QHostAddress::LocalHost, port);
    }

    bool waitEncrypted(int timeoutMs = 10000)
    {
        QElapsedTimer timer;
        timer.start();
        while (!isEncrypted() && state() != QAbstractSocket::UnconnectedState && timer.elapsed() < timeoutMs) {
            QTest::qWait(5);
        }
        return isEncrypted();
    }
};
}

class RelayServerTest : public QObject
{
    Q_OBJECT

private:
    std::unique_ptr<RelayServer> startServer(const RelayServerLimits &limits = {})
    {
        auto server = std::make_unique<RelayServer>(m_server.certificate, m_server.key, limits);
        if (!server->listen(QHostAddress::LocalHost, 0)) {
            return nullptr;
        }
        return server;
    }

    // Returns the token after checking both the tunnel reply and the incoming notification
    QString linkTunnel(Control &a, Control &b, const Target &target, const Identity &ia, const Identity &ib)
    {
        const QJsonObject tunnel = a.connect(target);
        const QJsonObject incoming = b.next();
        if (tunnel.value(QLatin1String("type")).toString() != QLatin1String("tunnel")
            || incoming.value(QLatin1String("type")).toString() != QLatin1String("incoming")) {
            return {};
        }
        const QString token = tunnel.value(QLatin1String("token")).toString();
        if (token.size() != 32 || incoming.value(QLatin1String("token")).toString() != token
            || tunnel.value(QLatin1String("peerFingerprint")).toString() != ib.fingerprint()
            || tunnel.value(QLatin1String("peerKey")).toString() != ib.relayKey()
            || incoming.value(QLatin1String("peerFingerprint")).toString() != ia.fingerprint()
            || incoming.value(QLatin1String("peerKey")).toString() != ia.relayKey()
            || tunnel.value(QLatin1String("purpose")).toString() != QLatin1String("link")) {
            return {};
        }
        return token;
    }

    Identity m_server, m_alice, m_bob, m_carol, m_dave;

private Q_SLOTS:
    void initTestCase()
    {
        m_server = Identity::load(QStringLiteral("server"));
        m_alice = Identity::load(QStringLiteral("alice"));
        m_bob = Identity::load(QStringLiteral("bob"));
        m_carol = Identity::load(QStringLiteral("carol"));
        m_dave = Identity::load(QStringLiteral("dave"));
        for (const Identity *id : {&m_server, &m_alice, &m_bob, &m_carol, &m_dave}) {
            QVERIFY(!id->certificate.isNull());
            QVERIFY(!id->key.isNull());
        }
        QCOMPARE(m_dave.key.algorithm(), QSsl::Rsa);
    }

    void testSharedTestVector()
    {
        QFile file(QFINDTESTDATA("data/relay-test-vector.pem"));
        QVERIFY(file.open(QIODevice::ReadOnly));
        const QSslCertificate certificate(file.readAll(), QSsl::Pem);
        QVERIFY(!certificate.isNull());
        // The KDE Connect desktop and Android clients assert the same values
        QCOMPARE(RelayProtocol::fingerprint(certificate), QStringLiteral("fc1fb3d3d33b2342e45c74b1a613dcdfe5e1f029d668249f504952a9a8041e31"));
        QCOMPARE(QString::fromLatin1(QCryptographicHash::hash(certificate.publicKey().toDer(), QCryptographicHash::Sha256).toHex()),
                 QStringLiteral("a2d2e306d0372fb596fd6f647a05d6b79054b5ee052ea58171efc3144d54fe8c"));
        QCOMPARE(RelayProtocol::relayKey(certificate), QStringLiteral("ULJO-GBWQ-G4X3-LFX5-N5SH"));
    }

    void testKeyDerivation()
    {
        QCOMPARE(m_alice.relayKey(), RelayProtocol::relayKey(QSslCertificate(m_alice.certificate.toPem())));
        QVERIFY(m_alice.relayKey() != m_bob.relayKey());
        QVERIFY(m_alice.relayKey() != m_dave.relayKey());
        QCOMPARE(m_dave.relayKey().size(), 24);

        // The key only depends on the public key, the fingerprint on the whole certificate
        QFile file(QFINDTESTDATA("data/alice-reissued.crt"));
        QVERIFY(file.open(QIODevice::ReadOnly));
        const QSslCertificate reissued(file.readAll(), QSsl::Pem);
        QCOMPARE(RelayProtocol::relayKey(reissued), m_alice.relayKey());
        QVERIFY(RelayProtocol::fingerprint(reissued) != m_alice.fingerprint());
        QVERIFY(RelayProtocol::relayKey(QSslCertificate()).isEmpty());
    }

    void testParseTarget()
    {
        QCOMPARE(RelayProtocol::parseTarget(QStringLiteral(" uljo gbwq-g4x3=lfx5n5sh ")), (Target{Target::Key, QStringLiteral("ULJO-GBWQ-G4X3-LFX5-N5SH")}));
        const QString colons = QStringLiteral("FC:1F:B3:D3:D3:3B:23:42:E4:5C:74:B1:A6:13:DC:DF:E5:E1:F0:29:D6:68:24:9F:50:49:52:A9:A8:04:1E:31");
        QCOMPARE(RelayProtocol::parseTarget(colons),
                 (Target{Target::Fingerprint, QStringLiteral("fc1fb3d3d33b2342e45c74b1a613dcdfe5e1f029d668249f504952a9a8041e31")}));
        QVERIFY(!RelayProtocol::parseTarget(QStringLiteral("ULJO-GBWQ-G4X3-LFX5-N5S1")).isValid()); // 1 is not base32
        QVERIFY(!RelayProtocol::parseTarget(QStringLiteral("ULJO-GBWQ-G4X3-LFX5")).isValid());
        QVERIFY(!RelayProtocol::parseTarget(QString(64, QLatin1Char('g'))).isValid());
        QVERIFY(!RelayProtocol::parseTarget(QString()).isValid());
        QVERIFY(!RelayProtocol::parseTarget(QStringLiteral("ULJO-GBWQ-G4X3-LFX5-N5S\u00c4")).isValid());

        const Target aliceKey = RelayProtocol::targetForCertificate(m_alice.certificate);
        QCOMPARE(aliceKey.kind, Target::Fingerprint);
        QVERIFY(RelayProtocol::matches(aliceKey, m_alice.certificate));
        QVERIFY(RelayProtocol::matches({Target::Key, m_alice.relayKey()}, m_alice.certificate));
        QVERIFY(!RelayProtocol::matches({Target::Key, m_alice.relayKey()}, m_bob.certificate));
        QVERIFY(!RelayProtocol::matches(aliceKey, m_bob.certificate));
        QVERIFY(!RelayProtocol::matches(Target(), m_alice.certificate));
        QVERIFY(!RelayProtocol::matches({Target::Key, m_alice.relayKey()}, QSslCertificate()));
    }

    void testMessageCodec()
    {
        const QJsonObject message{{QStringLiteral("type"), QStringLiteral("connect")}, {QStringLiteral("target"), QStringLiteral("x")}};
        const QByteArray line = RelayProtocol::encode(message);
        QVERIFY(line.endsWith('\n'));
        QCOMPARE(line.count('\n'), 1);
        QJsonObject decoded;
        QVERIFY(RelayProtocol::decode(line, &decoded));
        QCOMPARE(decoded, message);

        QVERIFY(!RelayProtocol::decode("{\"target\":\"x\"}\n", &decoded)); // No type
        QVERIFY(!RelayProtocol::decode("{\"type\":1}\n", &decoded));
        QVERIFY(!RelayProtocol::decode("[1,2]\n", &decoded));
        QVERIFY(!RelayProtocol::decode("{\"type\":\"x\"\n", &decoded));
        const QByteArray big = "{\"type\":\"x\",\"pad\":\"" + QByteArray(RelayProtocol::MaxLineSize, 'a') + "\"}\n";
        QVERIFY(!RelayProtocol::decode(big, &decoded));
    }

    void testParseAddress()
    {
        QString host;
        quint16 port = 0;
        QVERIFY(RelayProtocol::parseAddress(QStringLiteral("relay.example.org"), &host, &port));
        QCOMPARE(host, QStringLiteral("relay.example.org"));
        QCOMPARE(port, RelayProtocol::DefaultPort);
        QVERIFY(RelayProtocol::parseAddress(QStringLiteral(" 10.0.0.1:4000 "), &host, &port));
        QCOMPARE(host, QStringLiteral("10.0.0.1"));
        QCOMPARE(port, quint16(4000));
        QVERIFY(RelayProtocol::parseAddress(QStringLiteral("[::1]:99"), &host, &port));
        QCOMPARE(host, QStringLiteral("::1"));
        QCOMPARE(port, quint16(99));
        QVERIFY(RelayProtocol::parseAddress(QStringLiteral("fe80::1"), &host, &port));
        QCOMPARE(port, RelayProtocol::DefaultPort);
        QVERIFY(!RelayProtocol::parseAddress(QStringLiteral("host:0"), &host, &port));
        QVERIFY(!RelayProtocol::parseAddress(QStringLiteral("host:70000"), &host, &port));
        QVERIFY(!RelayProtocol::parseAddress(QStringLiteral(":1765"), &host, &port));
        QVERIFY(!RelayProtocol::parseAddress(QString(), &host, &port));
        QVERIFY(!RelayProtocol::parseAddress(QStringLiteral("[::1"), &host, &port));
        QVERIFY(!RelayProtocol::parseAddress(QStringLiteral("host name:1"), &host, &port));
    }

    void testRegistration()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control d(server->serverPort(), m_dave);
        QVERIFY(a.registered());
        QVERIFY(d.registered());
        QCOMPARE(a.welcome().value(QLatin1String("version")).toInt(), RelayProtocol::Version);
        QCOMPARE(a.welcome().value(QLatin1String("key")).toString(), m_alice.relayKey());
        QCOMPARE(a.welcome().value(QLatin1String("fingerprint")).toString(), m_alice.fingerprint());
        QCOMPARE(d.welcome().value(QLatin1String("key")).toString(), m_dave.relayKey());
        QCOMPARE(server->deviceCount(), 2);

        a.socket()->disconnectFromHost();
        QTRY_COMPARE(server->deviceCount(), 1);
    }

    void testClientCertificateRequired()
    {
        auto server = startServer();
        QVERIFY(server);
        QSslSocket socket;
        connect(&socket, &QSslSocket::sslErrors, &socket, [&socket](const QList<QSslError> &) {
            socket.ignoreSslErrors();
        });
        socket.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&socket));
        socket.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("version"), 1}}));
        QCOMPARE(readLine(&socket), RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("starttls")}}));
        socket.startClientEncryption();
        QVERIFY(waitEncrypted(&socket));
        QJsonObject reply;
        QVERIFY(RelayProtocol::decode(readLine(&socket), &reply));
        QCOMPARE(reply.value(QLatin1String("code")).toString(), QStringLiteral("bad_request"));
        QVERIFY(waitClosed(&socket));
        QCOMPARE(server->deviceCount(), 0);
    }

    void testHelloMustWaitForStartTls()
    {
        auto server = startServer();
        QVERIFY(server);
        QTcpSocket socket;
        socket.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&socket));
        // Bytes after hello in the same segment could be a ClientHello sent too early
        socket.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("version"), 1}}) + "\x16\x03\x01");
        QVERIFY(waitClosed(&socket));
    }

    void testLinkTunnelByKeyEndToEnd()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());

        const QString token = linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob);
        QVERIFY(!token.isEmpty());
        QCOMPARE(server->tunnelCount(), 1);

        Data da(server->serverPort(), token, Data::TlsServer, m_alice);
        Data db(server->serverPort(), token, Data::TlsClient, m_bob);
        QVERIFY(da.waitEncrypted());
        QVERIFY(db.waitEncrypted());
        // The relay forwards the TLS session untouched: each side sees the other's device certificate
        QCOMPARE(da.peerCertificate(), m_bob.certificate);
        QCOMPARE(db.peerCertificate(), m_alice.certificate);

        da.write("hello from alice\n");
        db.write("hello from bob\n");
        QCOMPARE(readLine(&db), QByteArray("hello from alice\n"));
        QCOMPARE(readLine(&da), QByteArray("hello from bob\n"));

        da.disconnectFromHost();
        QVERIFY(waitClosed(&db));
        QTRY_COMPARE(server->tunnelCount(), 0);
    }

    void testLinkTunnelByFingerprint()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());
        const QString colons = QString::fromLatin1(m_bob.certificate.digest(QCryptographicHash::Sha256).toHex(':').toUpper());
        QJsonObject tunnel = a.connect({Target::Fingerprint, colons});
        QCOMPARE(tunnel.value(QLatin1String("type")).toString(), QStringLiteral("tunnel"));
        QCOMPARE(tunnel.value(QLatin1String("peerFingerprint")).toString(), m_bob.fingerprint());
        QCOMPARE(b.next().value(QLatin1String("type")).toString(), QStringLiteral("incoming"));
    }

    void testPreSpliceBuffering()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());
        const QString token = linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob);
        QVERIFY(!token.isEmpty());

        // Plain TCP on both ends: data sent before the second side attaches must arrive after splicing
        QTcpSocket first, second;
        first.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&first));
        first.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), token}}) + "early bytes\n");
        QTest::qWait(100);
        second.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&second));
        QSignalSpy spliced(server.get(), &RelayServer::tunnelSpliced);
        second.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), token}}));
        QVERIFY(spliced.wait(5000));
        QCOMPARE(readLine(&second), QByteArray("early bytes\n"));

        // A used token cannot be attached a third time
        QTcpSocket third;
        third.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&third));
        third.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), token}}));
        QVERIFY(waitClosed(&third));
        QCOMPARE(first.state(), QAbstractSocket::ConnectedState);
    }

    void testPreSpliceBufferLimit()
    {
        RelayServerLimits limits;
        limits.preSpliceBufferSize = 1024;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());
        const QString token = linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob);
        QVERIFY(!token.isEmpty());
        QTcpSocket first;
        first.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&first));
        first.write(RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), token}}) + QByteArray(4096, 'x'));
        QVERIFY(waitClosed(&first));
        QTRY_COMPARE(server->tunnelCount(), 0);
    }

    void testWrongPeerCannotHijackTunnel()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());
        const QString token = linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob);
        QVERIFY(!token.isEmpty());

        // The relay splices whoever presents the token, so the pin at the endpoints is what rejects carol
        Data da(server->serverPort(), token, Data::TlsServer, m_alice);
        Data dc(server->serverPort(), token, Data::TlsClient, m_carol);
        QVERIFY(da.waitEncrypted());
        QVERIFY(!RelayProtocol::matches({Target::Key, m_bob.relayKey()}, da.peerCertificate()));
        QCOMPARE(da.peerCertificate(), m_carol.certificate);
    }

    void testPayloadTunnel()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());

        const QJsonObject tunnel = a.connect({Target::Fingerprint, m_bob.fingerprint()}, QStringLiteral("payload"), QStringLiteral("p1"));
        QCOMPARE(tunnel.value(QLatin1String("type")).toString(), QStringLiteral("tunnel"));
        QCOMPARE(tunnel.value(QLatin1String("purpose")).toString(), QStringLiteral("payload"));
        QCOMPARE(tunnel.value(QLatin1String("requestId")).toString(), QStringLiteral("p1"));
        QVERIFY(b.next(300).isEmpty()); // Payload tunnels are not announced to the target
        const QString token = tunnel.value(QLatin1String("token")).toString();

        const QByteArray data = pattern(4 * 1024 * 1024 + 123);
        Data sender(server->serverPort(), token, Data::TlsServer, m_alice);
        Data receiver(server->serverPort(), token, Data::TlsClient, m_bob);
        QVERIFY(sender.waitEncrypted());
        sender.write(data);
        QCOMPARE(readExactly(&receiver, data.size()), data);
    }

    void testConnectErrors()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        QCOMPARE(a.connectError({Target::Key, m_carol.relayKey()}), QStringLiteral("not_found"));
        QCOMPARE(a.connectError({Target::Fingerprint, m_carol.fingerprint()}), QStringLiteral("not_found"));
        QCOMPARE(a.connectError({Target::Key, m_alice.relayKey()}), QStringLiteral("self"));
        QCOMPARE(a.connectError({Target::Key, m_carol.relayKey()}, QStringLiteral("bogus")), QStringLiteral("bad_request"));
        QCOMPARE(a.connectError({Target::Key, QStringLiteral("not a key")}), QStringLiteral("bad_request"));

        a.send({{QStringLiteral("type"), QStringLiteral("dance")}});
        QCOMPARE(a.next().value(QLatin1String("code")).toString(), QStringLiteral("bad_request"));
        a.send({{QStringLiteral("type"), QStringLiteral("ping")}});
        QCOMPARE(a.next().value(QLatin1String("type")).toString(), QStringLiteral("pong"));
    }

    void testMalformedControlMessageDisconnects()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        a.socket()->write("this is not json\n");
        QCOMPARE(a.next().value(QLatin1String("code")).toString(), QStringLiteral("bad_request"));
        QVERIFY(waitClosed(a.socket()));
        QTRY_COMPARE(server->deviceCount(), 0);
    }

    void testInvalidFirstLine()
    {
        auto server = startServer();
        QVERIFY(server);
        const QList<QByteArray> lines{
            RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("attach")}, {QStringLiteral("token"), QStringLiteral("00112233")}}),
            "GET / HTTP/1.1\r\n\r\n",
            RelayProtocol::encode({{QStringLiteral("type"), QStringLiteral("hello")}, {QStringLiteral("version"), 99}}),
            QByteArray(RelayProtocol::MaxLineSize + 10, 'x'),
        };
        for (const QByteArray &line : lines) {
            QTcpSocket socket;
            socket.connectToHost(QHostAddress::LocalHost, server->serverPort());
            QVERIFY(waitConnected(&socket));
            socket.write(line);
            QVERIFY2(waitClosed(&socket), line.left(40).constData());
            // The server never answers anything but hello
            QCOMPARE(socket.bytesAvailable(), 0);
        }
    }

    void testHandshakeTimeout()
    {
        RelayServerLimits limits;
        limits.handshakeTimeoutMs = 200;
        auto server = startServer(limits);
        QVERIFY(server);
        QTcpSocket idle;
        idle.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&idle));
        QVERIFY(waitClosed(&idle, 3000));
    }

    void testControlIdleTimeout()
    {
        RelayServerLimits limits;
        limits.controlIdleTimeoutMs = 300;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        QVERIFY(waitClosed(a.socket(), 3000));
        QTRY_COMPARE(server->deviceCount(), 0);
    }

    void testConnectRateLimit()
    {
        RelayServerLimits limits;
        limits.connectBurst = 3;
        limits.connectRefillMs = 60000;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        for (int i = 0; i < 3; ++i) {
            QCOMPARE(a.connectError({Target::Key, m_carol.relayKey()}), QStringLiteral("not_found"));
        }
        QCOMPARE(a.connectError({Target::Key, m_carol.relayKey()}), QStringLiteral("rate_limited"));
    }

    void testConnectionsPerIpLimit()
    {
        RelayServerLimits limits;
        limits.maxConnectionsPerIp = 2;
        auto server = startServer(limits);
        QVERIFY(server);
        QTcpSocket s1, s2, s3;
        for (QTcpSocket *s : {&s1, &s2}) {
            s->connectToHost(QHostAddress::LocalHost, server->serverPort());
            QVERIFY(waitConnected(s));
        }
        QTest::qWait(100);
        s3.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&s3));
        QVERIFY(waitClosed(&s3));
        QCOMPARE(s1.state(), QAbstractSocket::ConnectedState);
    }

    void testNewConnectionsPerIpRate()
    {
        RelayServerLimits limits;
        limits.maxNewConnectionsPerIpPerMinute = 3;
        auto server = startServer(limits);
        QVERIFY(server);
        for (int i = 0; i < 3; ++i) {
            QTcpSocket s;
            s.connectToHost(QHostAddress::LocalHost, server->serverPort());
            QVERIFY(waitConnected(&s));
            s.disconnectFromHost();
            QTest::qWait(50);
        }
        QTcpSocket over;
        over.connectToHost(QHostAddress::LocalHost, server->serverPort());
        QVERIFY(waitConnected(&over));
        QVERIFY(waitClosed(&over));
    }

    void testMaxDevices()
    {
        RelayServerLimits limits;
        limits.maxDevices = 1;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        Control b(server->serverPort(), m_bob);
        QVERIFY(!b.registered());
        QCOMPARE(b.welcome().value(QLatin1String("code")).toString(), QStringLiteral("server_full"));
        QCOMPARE(server->deviceCount(), 1);
    }

    void testTooManyTunnels()
    {
        RelayServerLimits limits;
        limits.maxTunnelsPerDevice = 2;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());
        QCOMPARE(a.connectError({Target::Key, m_bob.relayKey()}), QStringLiteral("ok"));
        QVERIFY(!b.next().isEmpty()); // incoming
        QCOMPARE(a.connectError({Target::Key, m_bob.relayKey()}, QStringLiteral("payload")), QStringLiteral("ok"));
        QCOMPARE(a.connectError({Target::Key, m_bob.relayKey()}), QStringLiteral("too_many_tunnels"));
        // The limit counts tunnels of the target too
        QCOMPARE(b.connectError({Target::Key, m_alice.relayKey()}), QStringLiteral("too_many_tunnels"));
    }

    void testTokenExpiryAndIdleTimeout()
    {
        RelayServerLimits limits;
        limits.tokenExpiryMs = 300;
        limits.tunnelIdleTimeoutMs = 500;
        auto server = startServer(limits);
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());

        QVERIFY(!linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob).isEmpty());
        QCOMPARE(server->tunnelCount(), 1);
        QTRY_COMPARE_WITH_TIMEOUT(server->tunnelCount(), 0, 3000);

        const QString token = linkTunnel(a, b, {Target::Key, m_bob.relayKey()}, m_alice, m_bob);
        Data da(server->serverPort(), token, Data::TlsServer, m_alice);
        Data db(server->serverPort(), token, Data::TlsClient, m_bob);
        QVERIFY(da.waitEncrypted() && db.waitEncrypted());
        QVERIFY(waitClosed(&da, 3000)); // Idle timeout
        QCOMPARE(server->tunnelCount(), 0);
    }

    void testReplaced()
    {
        auto server = startServer();
        QVERIFY(server);
        Control first(server->serverPort(), m_alice);
        QVERIFY(first.registered());
        Control second(server->serverPort(), m_alice);
        QVERIFY(second.registered());
        const QJsonObject error = first.next();
        QCOMPARE(error.value(QLatin1String("type")).toString(), QStringLiteral("error"));
        QCOMPARE(error.value(QLatin1String("code")).toString(), QStringLiteral("replaced"));
        QVERIFY(waitClosed(first.socket()));
        QCOMPARE(server->deviceCount(), 1);

        // The new connection is the one that receives traffic
        Control b(server->serverPort(), m_bob);
        QVERIFY(b.registered());
        QCOMPARE(b.connectError({Target::Key, m_alice.relayKey()}), QStringLiteral("ok"));
        QCOMPARE(second.next().value(QLatin1String("type")).toString(), QStringLiteral("incoming"));
    }

    void testPeerOnlineRequiresMutualWatch()
    {
        auto server = startServer();
        QVERIFY(server);
        Control a(server->serverPort(), m_alice);
        Control b(server->serverPort(), m_bob);
        QVERIFY(a.registered() && b.registered());

        a.watch({m_bob.fingerprint()});
        QVERIFY(a.next(300).isEmpty());
        QVERIFY(b.next(100).isEmpty());

        b.watch({m_alice.fingerprint().toUpper()});
        const QJsonObject onlineB = b.next();
        const QJsonObject onlineA = a.next();
        QCOMPARE(onlineA.value(QLatin1String("type")).toString(), QStringLiteral("peer_online"));
        QCOMPARE(onlineA.value(QLatin1String("peerFingerprint")).toString(), m_bob.fingerprint());
        QCOMPARE(onlineA.value(QLatin1String("peerKey")).toString(), m_bob.relayKey());
        QCOMPARE(onlineB.value(QLatin1String("peerFingerprint")).toString(), m_alice.fingerprint());

        // Watch lists over the limit are refused
        QStringList many;
        for (int i = 0; i < RelayServerLimits().maxWatched + 1; ++i) {
            many.append(QString::number(i).repeated(64).left(64));
        }
        a.watch(many);
        QCOMPARE(a.next().value(QLatin1String("code")).toString(), QStringLiteral("bad_request"));
    }

    void testServerRestart()
    {
        auto server = startServer();
        QVERIFY(server);
        const quint16 port = server->serverPort();
        Control a(server->serverPort(), m_alice);
        QVERIFY(a.registered());
        server.reset();
        QVERIFY(waitClosed(a.socket()));

        server = std::make_unique<RelayServer>(m_server.certificate, m_server.key);
        QVERIFY(server->listen(QHostAddress::LocalHost, port));
        Control again(port, m_alice);
        QVERIFY(again.registered());
        QCOMPARE(again.welcome().value(QLatin1String("key")).toString(), m_alice.relayKey());
    }
};

QTEST_GUILESS_MAIN(RelayServerTest)

#include "relayservertest.moc"
