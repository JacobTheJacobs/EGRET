#pragma once

#include <QJsonObject>
#include <QMainWindow>
#include <QPointer>
#include <QQueue>
#include <QSet>

#include "ApiClient.h"

class ConnectionModel;
class ConnectionFilterProxy;
class RuleModel;
class PromptDialog;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSortFilterProxyModel;
class QStackedWidget;
class QTableView;
class QTextBrowser;
class QTimer;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(ApiClient *client, int pollSeconds, QWidget *parent = nullptr);

public slots:
    void captureNow();

    /// Tell the window a tray icon exists, so closing hides instead of exits.
    void setHasTray(bool hasTray) { m_hasTray = hasTray; }

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    QWidget *buildSidebar();
    QWidget *buildFilterChips();
    void updateDetail();
    void createRuleForSelection();
    void deleteSelectedRule();
    QWidget *buildConnectionsPage();
    QWidget *buildRulesPage();
    QWidget *buildHealthPage();
    QTableView *makeTable();

    void onConnections(const QList<Connection> &connections);
    void onRules(const QList<Rule> &rules);
    void onHealth(const QJsonObject &health);
    void onError(const QString &message);

    void queuePrompts(const QList<Connection> &connections);
    void drainPrompts();
    void setPromptsEnabled(bool enabled);
    void submitDecision(const Connection &connection, const QString &action, int ttlSeconds,
                        ApiClient::RuleScope scope);

    ApiClient *m_client;
    ConnectionModel *m_connectionModel;
    RuleModel *m_ruleModel;
    ConnectionFilterProxy *m_connectionFilter;
    QSortFilterProxyModel *m_ruleFilter;

    QStackedWidget *m_pages;
    QLineEdit *m_search;
    QTableView *m_connectionTable;
    QTableView *m_ruleTable;
    QTextBrowser *m_healthView;
    QLabel *m_connectionEmpty;
    QLabel *m_ruleEmpty;
    QPushButton *m_deleteRule;
    QLabel *m_detail;
    QPushButton *m_createRule;
    QLabel *m_statConnections = nullptr;
    QLabel *m_statRules = nullptr;
    QLabel *m_statPending = nullptr;
    QLabel *m_statUnpackaged = nullptr;
    QLabel *m_counts;
    QLabel *m_backendState;
    QTimer *m_pollTimer;

    /// Prompting is opt-in and capped; an un-throttled queue over a full
    /// connection list renders the desktop unusable.
    static constexpr int kMaxPendingPrompts = 5;
    static constexpr int kPromptCooldownMs = 1500;

    bool m_hasTray = false;
    bool m_promptsEnabled = false;
    QCheckBox *m_promptToggle;

    QSet<QString> m_decided;
    /// Processes answered with process-wide scope; never prompt for them again.
    QSet<QString> m_processDecided;
    QQueue<Connection> m_pending;
    QPointer<PromptDialog> m_openPrompt;
};
