#include "ApiClient.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace {

QString stringOr(const QJsonObject &object, const char *key, const QString &fallback = QString())
{
    const QJsonValue value = object.value(QLatin1String(key));
    return value.isString() ? value.toString() : fallback;
}

} // namespace

ApiClient::ApiClient(QString baseUrl, QObject *parent)
    : QObject(parent)
    , m_baseUrl(std::move(baseUrl))
    , m_network(new QNetworkAccessManager(this))
{
    while (m_baseUrl.endsWith('/'))
        m_baseUrl.chop(1);
}

QJsonObject ApiClient::readJson(QNetworkReply *reply, bool *ok)
{
    reply->deleteLater();
    *ok = false;
    if (reply->error() != QNetworkReply::NoError) {
        emit errorOccurred(reply->errorString());
        return {};
    }
    const QJsonDocument document = QJsonDocument::fromJson(reply->readAll());
    if (!document.isObject()) {
        emit errorOccurred(QStringLiteral("Malformed JSON from %1").arg(reply->url().toString()));
        return {};
    }
    *ok = true;
    return document.object();
}

void ApiClient::get(const QString &path, void (ApiClient::*handler)(QNetworkReply *))
{
    QNetworkRequest request{QUrl(m_baseUrl + path)};
    request.setRawHeader("Accept", "application/json");
    QNetworkReply *reply = m_network->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, handler] { (this->*handler)(reply); });
}

void ApiClient::refresh()
{
    get(QStringLiteral("/api/v1/connections?page_size=500"), &ApiClient::handleConnections);
    get(QStringLiteral("/api/v1/rules"), &ApiClient::handleRules);
    get(QStringLiteral("/api/v1/health/status"), &ApiClient::handleHealth);
}

void ApiClient::captureHost()
{
    QNetworkRequest request{QUrl(m_baseUrl + QStringLiteral("/api/v1/connections/capture-host"))};
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    const QByteArray body = QJsonDocument(QJsonObject{{"limit", 200}}).toJson(QJsonDocument::Compact);

    QNetworkReply *reply = m_network->post(request, body);
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            emit errorOccurred(reply->errorString());
            return;
        }
        refresh();
    });
}

void ApiClient::createRule(const Connection &connection, const QString &action, int ttlSeconds, RuleScope scope)
{
    // Scope decides how many future prompts this one answer silences. Address
    // scope is precise but a CDN rotates addresses constantly, so it re-prompts;
    // domain and process scope are what actually stop prompt fatigue.
    QJsonObject conditions{{"process_name", connection.processName}};
    QString scopeLabel;
    switch (scope) {
    case RuleScope::Address:
        if (!connection.ip.isEmpty())
            conditions.insert(QStringLiteral("remote_ip"), connection.ip);
        if (connection.port > 0)
            conditions.insert(QStringLiteral("remote_port"), connection.port);
        scopeLabel = connection.ip;
        break;
    case RuleScope::Domain:
        // Suffix match so sub-domains of the same service are covered too.
        conditions.insert(QStringLiteral("domain_suffix"), connection.ruleDomain());
        scopeLabel = connection.ruleDomain();
        break;
    case RuleScope::Process:
        scopeLabel = QStringLiteral("any destination");
        break;
    }

    QJsonObject payload{
        {"rule_name", QStringLiteral("%1 %2 to %3")
                          .arg(action == QLatin1String("allow") ? QStringLiteral("Allow") : QStringLiteral("Deny"),
                               connection.processName, scopeLabel)},
        {"action", action},
        {"source", QStringLiteral("user")},
        {"created_by", QStringLiteral("native-qt")},
        {"conditions", conditions},
    };
    payload.insert(QStringLiteral("ttl_seconds"), ttlSeconds > 0 ? QJsonValue(ttlSeconds) : QJsonValue());

    QNetworkRequest request{QUrl(m_baseUrl + QStringLiteral("/api/v1/rules"))};
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QNetworkReply *reply = m_network->post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            emit errorOccurred(reply->errorString());
            return;
        }
        emit ruleCreated();
        refresh();
    });
}

void ApiClient::deleteRule(const QString &ruleId)
{
    QNetworkRequest request{QUrl(m_baseUrl + QStringLiteral("/api/v1/rules/") + ruleId)};
    QNetworkReply *reply = m_network->deleteResource(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            emit errorOccurred(reply->errorString());
            return;
        }
        refresh();
    });
}

void ApiClient::handleConnections(QNetworkReply *reply)
{
    bool ok = false;
    const QJsonObject root = readJson(reply, &ok);
    if (!ok)
        return;

    QList<Connection> connections;
    const QJsonArray items = root.value(QStringLiteral("items")).toArray();
    connections.reserve(items.size());
    for (const QJsonValue &item : items) {
        const QJsonObject row = item.toObject();
        const QJsonObject process = row.value(QStringLiteral("process")).toObject();
        const QJsonObject destination = row.value(QStringLiteral("destination")).toObject();

        Connection connection;
        connection.connectionId = stringOr(row, "connection_id");
        connection.processName = stringOr(process, "name", stringOr(process, "process_name", QStringLiteral("unknown")));
        connection.processPath = stringOr(process, "path", stringOr(process, "process_path", QStringLiteral("unknown")));
        connection.signerStatus = stringOr(process, "signer_status");
        connection.signerName = stringOr(process, "signer_name");
        connection.packageId = stringOr(process, "package_id");
        connection.ip = stringOr(destination, "ip");
        connection.domain = stringOr(destination, "matched_domain", stringOr(destination, "sni"));
        connection.protocol = stringOr(destination, "protocol");
        connection.port = destination.value(QStringLiteral("port")).toInt();
        connection.verdict = stringOr(row, "verdict");
        connections.append(connection);
    }
    emit connectionsReceived(connections);
}

void ApiClient::handleRules(QNetworkReply *reply)
{
    bool ok = false;
    const QJsonObject root = readJson(reply, &ok);
    if (!ok)
        return;

    QList<Rule> rules;
    const QJsonArray items = root.value(QStringLiteral("items")).toArray();
    rules.reserve(items.size());
    for (const QJsonValue &item : items) {
        const QJsonObject row = item.toObject();
        const QJsonObject conditions = row.value(QStringLiteral("conditions")).toObject();

        Rule rule;
        rule.ruleId = stringOr(row, "rule_id");
        rule.ruleName = stringOr(row, "rule_name");
        rule.action = stringOr(row, "action");
        rule.processName = stringOr(conditions, "process_name", QStringLiteral("any process"));
        rule.target = stringOr(conditions, "domain",
                               stringOr(conditions, "domain_suffix",
                                        stringOr(conditions, "remote_ip", QStringLiteral("any"))));
        rule.enabled = row.value(QStringLiteral("enabled")).toBool(true);
        rule.ttlSeconds = row.value(QStringLiteral("ttl_seconds")).toInt();
        rule.createdTs = QDateTime::fromString(stringOr(row, "created_ts"), Qt::ISODateWithMs);
        rule.createdTs.setTimeSpec(Qt::UTC);
        rules.append(rule);
    }
    emit rulesReceived(rules);
}

void ApiClient::handleHealth(QNetworkReply *reply)
{
    bool ok = false;
    const QJsonObject root = readJson(reply, &ok);
    if (ok)
        emit healthReceived(root);
}
