/**
 * SPDX-FileCopyrightText: 2026 meatybot <avatarcc@tuta.io>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "relayprotocol.h"

#include <QCryptographicHash>
#include <QJsonDocument>
#include <QSslKey>

namespace RelayProtocol
{

QString fingerprint(const QSslCertificate &certificate)
{
    if (certificate.isNull()) {
        return QString();
    }
    return QString::fromLatin1(certificate.digest(QCryptographicHash::Sha256).toHex());
}

QString relayKeyFromPublicKeyDer(const QByteArray &spkiDer)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const QByteArray hash = QCryptographicHash::hash(spkiDer, QCryptographicHash::Sha256);

    QString key;
    key.reserve(KeyLength + KeyLength / 4);
    for (int i = 0; i < KeyLength; ++i) {
        // Read 5 bits starting at bit i * 5, most significant bit first
        const int bit = i * 5;
        const int byte = bit / 8;
        const int shift = bit % 8;
        int value = (static_cast<uchar>(hash[byte]) << 8) | static_cast<uchar>(hash[byte + 1]);
        value = (value >> (11 - shift)) & 0x1f;
        if (i > 0 && i % 4 == 0) {
            key += QLatin1Char('-');
        }
        key += QLatin1Char(alphabet[value]);
    }
    return key;
}

QString relayKey(const QSslCertificate &certificate)
{
    if (certificate.isNull()) {
        return QString();
    }
    return relayKeyFromPublicKeyDer(certificate.publicKey().toDer());
}

Target parseTarget(const QString &input)
{
    QString compact;
    compact.reserve(input.size());
    for (const QChar c : input) {
        if (c == QLatin1Char('-') || c == QLatin1Char(':') || c == QLatin1Char('=') || c.isSpace()) {
            continue;
        }
        if (c.unicode() > 127) {
            return {};
        }
        compact += c.toUpper();
    }

    if (compact.size() == 64) {
        for (const QChar c : std::as_const(compact)) {
            if (!((c >= QLatin1Char('0') && c <= QLatin1Char('9')) || (c >= QLatin1Char('A') && c <= QLatin1Char('F')))) {
                return {};
            }
        }
        return {Target::Fingerprint, compact.toLower()};
    }

    if (compact.size() == KeyLength) {
        QString grouped;
        for (int i = 0; i < compact.size(); ++i) {
            const QChar c = compact[i];
            if (!((c >= QLatin1Char('A') && c <= QLatin1Char('Z')) || (c >= QLatin1Char('2') && c <= QLatin1Char('7')))) {
                return {};
            }
            if (i > 0 && i % 4 == 0) {
                grouped += QLatin1Char('-');
            }
            grouped += c;
        }
        return {Target::Key, grouped};
    }

    return {};
}

Target targetForCertificate(const QSslCertificate &certificate)
{
    if (certificate.isNull()) {
        return {};
    }
    return {Target::Fingerprint, fingerprint(certificate)};
}

bool matches(const Target &target, const QSslCertificate &certificate)
{
    if (certificate.isNull()) {
        return false;
    }
    switch (target.kind) {
    case Target::Key:
        return relayKey(certificate) == target.value;
    case Target::Fingerprint:
        return fingerprint(certificate) == target.value;
    case Target::Invalid:
        break;
    }
    return false;
}

QByteArray encode(const QJsonObject &message)
{
    QByteArray line = QJsonDocument(message).toJson(QJsonDocument::Compact);
    line += '\n';
    return line;
}

bool decode(const QByteArray &line, QJsonObject *message)
{
    if (line.size() > MaxLineSize) {
        return false;
    }
    QJsonParseError error;
    const QJsonDocument doc = QJsonDocument::fromJson(line.trimmed(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        return false;
    }
    const QJsonObject object = doc.object();
    if (!object.value(QLatin1String("type")).isString()) {
        return false;
    }
    *message = object;
    return true;
}

bool parseAddress(const QString &address, QString *host, quint16 *port)
{
    const QString trimmed = address.trimmed();
    if (trimmed.isEmpty()) {
        return false;
    }

    QString hostPart = trimmed;
    QString portPart;
    bool ipv6 = false;
    if (trimmed.startsWith(QLatin1Char('['))) {
        ipv6 = true;
        const int end = trimmed.indexOf(QLatin1Char(']'));
        if (end < 0) {
            return false;
        }
        hostPart = trimmed.mid(1, end - 1);
        const QString rest = trimmed.mid(end + 1);
        if (!rest.isEmpty()) {
            if (!rest.startsWith(QLatin1Char(':'))) {
                return false;
            }
            portPart = rest.mid(1);
        }
    } else if (trimmed.count(QLatin1Char(':')) == 1) {
        const int colon = trimmed.indexOf(QLatin1Char(':'));
        hostPart = trimmed.left(colon);
        portPart = trimmed.mid(colon + 1);
    } else if (trimmed.contains(QLatin1Char(':'))) {
        ipv6 = true;
    }

    // Host names and IPv4: letters, digits, '-' and '.'. IPv6: hex digits, ':' and '.'
    if (hostPart.isEmpty()) {
        return false;
    }
    for (const QChar c : std::as_const(hostPart)) {
        const bool hex = (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || (c >= QLatin1Char('a') && c <= QLatin1Char('f'))
            || (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
        const bool valid = ipv6 ? (hex || c == QLatin1Char(':') || c == QLatin1Char('.'))
                                : (hex || (c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('A') && c <= QLatin1Char('Z'))
                                   || c == QLatin1Char('-') || c == QLatin1Char('.'));
        if (!valid) {
            return false;
        }
    }

    quint16 parsedPort = DefaultPort;
    if (!portPart.isNull()) {
        bool ok = false;
        const uint value = portPart.toUInt(&ok);
        if (!ok || value == 0 || value > 65535) {
            return false;
        }
        parsedPort = static_cast<quint16>(value);
    }

    *host = hostPart;
    *port = parsedPort;
    return true;
}

}
