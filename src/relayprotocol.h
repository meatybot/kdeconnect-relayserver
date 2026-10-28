/**
 * SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef RELAYPROTOCOL_H
#define RELAYPROTOCOL_H

#include <QByteArray>
#include <QJsonObject>
#include <QSslCertificate>
#include <QString>

// Shared between the relay client backend and the standalone relay server (QtCore + QtNetwork only).
// See docs/protocol.md
namespace RelayProtocol
{
constexpr int Version = 1;
constexpr quint16 DefaultPort = 1765;
constexpr int MaxLineSize = 8192;
constexpr int KeyLength = 20; // base32 characters, 100 bits

// SHA-256 over the DER certificate, 64 lowercase hex characters
QString fingerprint(const QSslCertificate &certificate);

// First 100 bits of SHA-256 over the DER SubjectPublicKeyInfo, base32, grouped as XXXX-XXXX-XXXX-XXXX-XXXX
QString relayKey(const QSslCertificate &certificate);
QString relayKeyFromPublicKeyDer(const QByteArray &spkiDer);

struct Target {
    enum Kind {
        Invalid,
        Key,
        Fingerprint,
    };
    Kind kind = Invalid;
    QString value; // Normalized: grouped key, or lowercase hex fingerprint

    bool isValid() const
    {
        return kind != Invalid;
    }
    bool operator==(const Target &other) const
    {
        return kind == other.kind && value == other.value;
    }
};

// Accepts a relay key or a fingerprint in any case, ignoring '-', ':', '=' and whitespace
Target parseTarget(const QString &input);
Target targetForCertificate(const QSslCertificate &certificate);
bool matches(const Target &target, const QSslCertificate &certificate);

// One JSON object per line, at most MaxLineSize bytes including the newline
QByteArray encode(const QJsonObject &message);
// Returns false for oversized lines, invalid JSON or a missing "type"
bool decode(const QByteArray &line, QJsonObject *message);

// "host", "host:port", "[v6addr]:port" or "v6addr"
bool parseAddress(const QString &address, QString *host, quint16 *port);
}

#endif
