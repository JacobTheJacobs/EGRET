#pragma once

#include <QJsonObject>
#include <QList>
#include <QDateTime>
#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

/// One captured outbound flow, flattened from the /api/v1/connections payload.
struct Connection {
    QString connectionId;
    QString processName;
    QString processPath;
    QString signerStatus;
    QString signerName;
    QString packageId;
    QString ip;
    QString domain;
    QString protocol;
    int port = 0;
    QString verdict;

    /// Domain when the backend resolved one, otherwise the bare address.
    QString target() const { return domain.isEmpty() ? ip : domain; }

    /// Stable identity used to avoid prompting twice for the same flow.
    QString key() const { return processName + '|' + target() + '|' + QString::number(port); }

    bool hasDomain() const { return !domain.isEmpty(); }

    /// The suffix a domain-scoped rule should match.
    ///
    /// Collapses a host to its last two labels, so one answer covers the whole
    /// service rather than a single rotating CDN node
    /// (lhr48s28-in-f14.1e100.net -> 1e100.net).
    QString ruleDomain() const
    {
        const QStringList labels = domain.split('.', Qt::SkipEmptyParts);
        if (labels.size() <= 2)
            return domain;
        return labels.mid(labels.size() - 2).join('.');
    }

    /// Short trust word shown in the table: what the binary is, not who ran it.
    QString trust() const
    {
        if (signerStatus == QLatin1String("trusted"))
            return QStringLiteral("trusted");
        if (signerStatus == QLatin1String("unsigned"))
            return QStringLiteral("unsigned");
        return QStringLiteral("unknown");
    }

    bool unsigned_or_unknown() const {
        return signerStatus.isEmpty() || signerStatus == QLatin1String("unsigned")
            || signerStatus == QLatin1String("unknown");
    }
};

struct Rule {
    QString ruleId;
    QString ruleName;
    QString action;
    QString processName;
    QString target;
    bool enabled = true;
    int ttlSeconds = 0;          ///< 0 means the rule never expires.
    QDateTime createdTs;

    /// When a temporary rule lapses; invalid for a permanent one.
    QDateTime expiresAt() const
    {
        if (ttlSeconds <= 0 || !createdTs.isValid())
            return {};
        return createdTs.addSecs(ttlSeconds);
    }

    /// Expired rules stay in the table until the next maintenance pass, but the
    /// evaluator already ignores them, so the list must not imply they apply.
    bool hasLapsed() const
    {
        const QDateTime end = expiresAt();
        return end.isValid() && end <= QDateTime::currentDateTimeUtc();
    }
};

/// Asynchronous client for the Egret HTTP API.
///
/// The native client never touches SQLite or app.services directly; every read
/// and write goes through the same REST surface the web UI uses.
class ApiClient : public QObject {
    Q_OBJECT

public:
    explicit ApiClient(QString baseUrl, QObject *parent = nullptr);

    /// How broadly a decision should apply.
    enum class RuleScope {
        Address, ///< this exact address and port
        Domain,  ///< any address serving this domain (suffix match)
        Process, ///< every destination this process reaches
    };

    void refresh();
    void captureHost();
    void createRule(const Connection &connection, const QString &action, int ttlSeconds, RuleScope scope);
    void deleteRule(const QString &ruleId);

signals:
    void connectionsReceived(const QList<Connection> &connections);
    void rulesReceived(const QList<Rule> &rules);
    void healthReceived(const QJsonObject &health);
    void ruleCreated();
    void errorOccurred(const QString &message);

private:
    void get(const QString &path, void (ApiClient::*handler)(QNetworkReply *));
    void handleConnections(QNetworkReply *reply);
    void handleRules(QNetworkReply *reply);
    void handleHealth(QNetworkReply *reply);
    QJsonObject readJson(QNetworkReply *reply, bool *ok);

    QString m_baseUrl;
    QNetworkAccessManager *m_network;
};
