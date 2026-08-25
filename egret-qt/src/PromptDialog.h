#pragma once

#include <QDialog>

#include "ApiClient.h"

class QComboBox;

/// Always-on-top Allow/Deny prompt for a connection the policy engine could not
/// decide on. This is the piece a browser tab structurally cannot provide.
class PromptDialog : public QDialog {
    Q_OBJECT

public:
    explicit PromptDialog(const Connection &connection, QWidget *parent = nullptr);

    const Connection &connection() const { return m_connection; }

signals:
    /// action is "allow" or "deny"; ttlSeconds of 0 means a permanent rule.
    void decided(const Connection &connection, const QString &action, int ttlSeconds,
                 ApiClient::RuleScope scope);

private:
    void decide(const QString &action, int ttlSeconds);
    ApiClient::RuleScope selectedScope() const;

    Connection m_connection;
    QComboBox *m_scope;
};
