#include "MainWindow.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QShortcut>
#include <QSortFilterProxyModel>
#include <QStackedWidget>
#include <QStatusBar>
#include <QSystemTrayIcon>
#include <QTableView>
#include <QTextBrowser>
#include <QTimer>
#include <QVBoxLayout>

#include "BadgeDelegate.h"
#include "ConnectionModel.h"
#include "PromptDialog.h"
#include "Theme.h"

namespace {

QLabel *pageTitle(const QString &text)
{
    auto *label = new QLabel(text);
    label->setObjectName(QStringLiteral("PageTitle"));
    return label;
}

QString escape(const QString &value)
{
    return value.toHtmlEscaped();
}

} // namespace

MainWindow::MainWindow(ApiClient *client, int pollSeconds, QWidget *parent)
    : QMainWindow(parent)
    , m_client(client)
    , m_connectionModel(new ConnectionModel(this))
    , m_ruleModel(new RuleModel(this))
    , m_connectionFilter(new ConnectionFilterProxy(this))
    , m_ruleFilter(new QSortFilterProxyModel(this))
    , m_pollTimer(new QTimer(this))
{
    setWindowTitle(tr("Egret"));
    resize(940, 620);

    m_connectionFilter->setSourceModel(m_connectionModel);
    m_connectionFilter->setFilterKeyColumn(-1);
    m_connectionFilter->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_ruleFilter->setSourceModel(m_ruleModel);
    m_ruleFilter->setFilterKeyColumn(-1);
    m_ruleFilter->setFilterCaseSensitivity(Qt::CaseInsensitive);

    m_pages = new QStackedWidget;
    m_pages->addWidget(buildConnectionsPage());
    m_pages->addWidget(buildRulesPage());
    m_pages->addWidget(buildHealthPage());

    auto *central = new QWidget;
    auto *layout = new QHBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(buildSidebar());
    layout->addWidget(m_pages, 1);
    setCentralWidget(central);

    m_counts = new QLabel;
    m_backendState = new QLabel;
    statusBar()->addWidget(m_counts, 1);
    statusBar()->addPermanentWidget(m_backendState);

    connect(m_client, &ApiClient::connectionsReceived, this, &MainWindow::onConnections);
    connect(m_client, &ApiClient::rulesReceived, this, &MainWindow::onRules);
    connect(m_client, &ApiClient::healthReceived, this, &MainWindow::onHealth);
    connect(m_client, &ApiClient::errorOccurred, this, &MainWindow::onError);

    new QShortcut(QKeySequence(QKeySequence::Refresh), this, [this] { captureNow(); });
    new QShortcut(QKeySequence(QStringLiteral("Ctrl+R")), this, [this] { captureNow(); });
    new QShortcut(QKeySequence(QKeySequence::Find), this, [this] {
        m_pages->setCurrentIndex(0);
        m_search->setFocus();
        m_search->selectAll();
    });

    connect(m_pollTimer, &QTimer::timeout, this, &MainWindow::captureNow);
    m_pollTimer->start(pollSeconds * 1000);
    captureNow();
}

QWidget *MainWindow::buildSidebar()
{
    auto *sidebar = new QWidget;
    sidebar->setObjectName(QStringLiteral("Sidebar"));
    sidebar->setFixedWidth(186);

    auto *layout = new QVBoxLayout(sidebar);
    layout->setContentsMargins(10, 8, 10, 10);
    layout->setSpacing(3);

    auto *brand = new QLabel(tr("Egret"));
    brand->setObjectName(QStringLiteral("Brand"));
    layout->addWidget(brand);

    auto *group = new QButtonGroup(this);
    const QStringList titles{tr("Connections"), tr("Rules"), tr("Health")};
    for (int i = 0; i < titles.size(); ++i) {
        auto *button = new QPushButton(titles.at(i));
        button->setCheckable(true);
        button->setChecked(i == 0);
        button->setCursor(Qt::PointingHandCursor);
        group->addButton(button, i);
        layout->addWidget(button);
    }
    connect(group, &QButtonGroup::idClicked, m_pages, &QStackedWidget::setCurrentIndex);

    layout->addStretch();

    m_promptToggle = new QCheckBox(tr("Ask on new"));
    m_promptToggle->setToolTip(tr("Prompt to allow or deny connections with no matching rule.\n"
                                  "Off by default — a fresh host has dozens of undecided connections."));
    m_promptToggle->setChecked(false);
    connect(m_promptToggle, &QCheckBox::toggled, this, &MainWindow::setPromptsEnabled);
    layout->addWidget(m_promptToggle);

    auto *capture = new QPushButton(tr("Capture now"));
    capture->setToolTip(tr("Poll host sockets immediately (Ctrl+R)"));
    connect(capture, &QPushButton::clicked, this, &MainWindow::captureNow);
    layout->addWidget(capture);

    return sidebar;
}

QTableView *MainWindow::makeTable()
{
    auto *table = new QTableView;
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true);
    table->setShowGrid(false);
    table->setSortingEnabled(true);
    table->setWordWrap(false);
    table->verticalHeader()->setVisible(false);
    table->verticalHeader()->setDefaultSectionSize(34);
    table->horizontalHeader()->setHighlightSections(false);
    table->horizontalHeader()->setStretchLastSection(false);
    return table;
}

QWidget *MainWindow::buildFilterChips()
{
    auto *bar = new QWidget;
    auto *layout = new QHBoxLayout(bar);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    struct Chip {
        QString label;
        ConnectionFilterProxy::Category category;
        QString hint;
    };
    const QList<Chip> chips{
        {tr("All"), ConnectionFilterProxy::Category::All, tr("Every captured connection")},
        {tr("Needs review"), ConnectionFilterProxy::Category::NeedsReview,
         tr("No rule matches yet — these are the ones awaiting a decision")},
        {tr("Unpackaged"), ConnectionFilterProxy::Category::Unsigned,
         tr("Binaries no package owns: they did not arrive through a signed repository")},
        {tr("Allowed"), ConnectionFilterProxy::Category::Allowed, tr("Permitted by a rule")},
        {tr("Denied"), ConnectionFilterProxy::Category::Denied, tr("Blocked by a rule")},
    };

    auto *group = new QButtonGroup(this);
    group->setExclusive(true);
    for (int i = 0; i < chips.size(); ++i) {
        const Chip &chip = chips.at(i);
        auto *button = new QPushButton(chip.label);
        button->setObjectName(QStringLiteral("Chip"));
        button->setCheckable(true);
        button->setChecked(i == 0);
        button->setCursor(Qt::PointingHandCursor);
        button->setToolTip(chip.hint);
        group->addButton(button, i);
        layout->addWidget(button);
        connect(button, &QPushButton::clicked, this,
                [this, category = chip.category] { m_connectionFilter->setCategory(category); });
    }
    layout->addStretch();
    return bar;
}

QWidget *MainWindow::buildConnectionsPage()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 16, 18, 12);
    layout->setSpacing(10);

    auto *header = new QHBoxLayout;
    header->addWidget(pageTitle(tr("Connections")));
    header->addStretch();

    m_search = new QLineEdit;
    m_search->setPlaceholderText(tr("Filter by process, destination, verdict…  (Ctrl+F)"));
    m_search->setClearButtonEnabled(true);
    m_search->setFixedWidth(330);
    connect(m_search, &QLineEdit::textChanged, m_connectionFilter, &QSortFilterProxyModel::setFilterFixedString);
    header->addWidget(m_search);
    layout->addLayout(header);
    layout->addWidget(buildFilterChips());

    m_connectionTable = makeTable();
    m_connectionTable->setModel(m_connectionFilter);
    m_connectionTable->sortByColumn(ConnectionModel::ProcessColumn, Qt::AscendingOrder);
    auto *headerView = m_connectionTable->horizontalHeader();
    headerView->setSectionResizeMode(ConnectionModel::ProcessColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(ConnectionModel::TargetColumn, QHeaderView::Stretch);
    headerView->setSectionResizeMode(ConnectionModel::PortColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(ConnectionModel::ProtocolColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(ConnectionModel::TrustColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(ConnectionModel::VerdictColumn, QHeaderView::ResizeToContents);

    // Pills rather than coloured words: a shape reads faster than a hue, and
    // still separates for anyone who cannot distinguish red from green.
    auto *badges = new BadgeDelegate(this);
    m_connectionTable->setItemDelegateForColumn(ConnectionModel::TrustColumn, badges);
    m_connectionTable->setItemDelegateForColumn(ConnectionModel::VerdictColumn, badges);
    layout->addWidget(m_connectionTable, 1);

    // Selecting a row answers "what is this thing?" without a second window.
    auto *detailRow = new QWidget;
    detailRow->setObjectName(QStringLiteral("DetailBar"));
    auto *detailLayout = new QHBoxLayout(detailRow);
    detailLayout->setContentsMargins(12, 8, 10, 8);
    detailLayout->setSpacing(12);

    m_detail = new QLabel;
    m_detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_detail->setWordWrap(true);
    m_detail->setText(tr("Select a connection to see the binary behind it."));
    detailLayout->addWidget(m_detail, 1);

    // Rules previously existed only as an answer to a prompt, which meant there
    // was no way to decide about a connection you were looking at right now.
    m_createRule = new QPushButton(tr("Allow or deny…"));
    m_createRule->setEnabled(false);
    m_createRule->setCursor(Qt::PointingHandCursor);
    m_createRule->setToolTip(tr("Create a rule for the selected connection"));
    connect(m_createRule, &QPushButton::clicked, this, &MainWindow::createRuleForSelection);
    detailLayout->addWidget(m_createRule);

    layout->addWidget(detailRow);
    connect(m_connectionTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::updateDetail);
    connect(m_connectionTable, &QTableView::doubleClicked, this, &MainWindow::createRuleForSelection);

    m_connectionEmpty = new QLabel(tr("No connections captured yet — press Capture now."));
    m_connectionEmpty->setAlignment(Qt::AlignCenter);
    m_connectionEmpty->setStyleSheet(QStringLiteral("color: %1; padding: 30px;").arg(Theme::textDim().name()));
    m_connectionEmpty->hide();
    layout->addWidget(m_connectionEmpty);

    return page;
}

QWidget *MainWindow::buildRulesPage()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 16, 18, 12);
    layout->setSpacing(10);

    auto *header = new QHBoxLayout;
    header->addWidget(pageTitle(tr("Rules")));
    header->addStretch();

    auto *filter = new QLineEdit;
    filter->setPlaceholderText(tr("Filter rules…"));
    filter->setClearButtonEnabled(true);
    filter->setFixedWidth(260);
    connect(filter, &QLineEdit::textChanged, m_ruleFilter, &QSortFilterProxyModel::setFilterFixedString);
    header->addWidget(filter);

    // A decision you cannot take back is not a decision you can make safely.
    m_deleteRule = new QPushButton(tr("Delete rule"));
    m_deleteRule->setObjectName(QStringLiteral("Danger"));
    m_deleteRule->setEnabled(false);
    m_deleteRule->setCursor(Qt::PointingHandCursor);
    connect(m_deleteRule, &QPushButton::clicked, this, &MainWindow::deleteSelectedRule);
    header->addWidget(m_deleteRule);
    layout->addLayout(header);

    m_ruleTable = makeTable();
    m_ruleTable->setModel(m_ruleFilter);
    m_ruleTable->setItemDelegateForColumn(RuleModel::ActionColumn, new BadgeDelegate(this));
    connect(m_ruleTable->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex &current) { m_deleteRule->setEnabled(current.isValid()); });
    auto *headerView = m_ruleTable->horizontalHeader();
    headerView->setSectionResizeMode(RuleModel::NameColumn, QHeaderView::Stretch);
    headerView->setSectionResizeMode(RuleModel::ProcessColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(RuleModel::TargetColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(RuleModel::ExpiresColumn, QHeaderView::ResizeToContents);
    headerView->setSectionResizeMode(RuleModel::ActionColumn, QHeaderView::ResizeToContents);
    layout->addWidget(m_ruleTable, 1);

    // An empty rule list is the normal starting state, not a fault. Say how
    // rules come to exist rather than leaving a blank table.
    m_ruleEmpty = new QLabel(
        tr("No rules yet.\n\n"
           "Two ways to make one:\n\n"
           "Pick a connection on the Connections tab and press "
           "\u201cAllow or deny\u2026\u201d — or double-click it.\n\n"
           "Or turn on \u201cAsk on new\u201d in the sidebar, and Egret will ask you "
           "about connections no rule covers as they appear."));
    m_ruleEmpty->setAlignment(Qt::AlignCenter);
    m_ruleEmpty->setWordWrap(true);
    m_ruleEmpty->setStyleSheet(
        QStringLiteral("color: %1; padding: 34px;").arg(Theme::textDim().name()));
    layout->addWidget(m_ruleEmpty);

    return page;
}

namespace {

/// A labelled figure, used for the counters across the top of Health.
QFrame *statCard(const QString &label, QLabel **valueOut)
{
    auto *card = new QFrame;
    card->setObjectName(QStringLiteral("Card"));
    auto *layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 12, 14, 12);
    layout->setSpacing(2);

    auto *value = new QLabel(QStringLiteral("—"));
    value->setObjectName(QStringLiteral("CardValue"));
    auto *caption = new QLabel(label);
    caption->setObjectName(QStringLiteral("CardLabel"));

    layout->addWidget(value);
    layout->addWidget(caption);
    *valueOut = value;
    return card;
}

} // namespace

QWidget *MainWindow::buildHealthPage()
{
    auto *page = new QWidget;
    auto *layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 16, 18, 12);
    layout->setSpacing(12);
    layout->addWidget(pageTitle(tr("Health")));

    auto *cards = new QHBoxLayout;
    cards->setSpacing(10);
    cards->addWidget(statCard(tr("Connections"), &m_statConnections));
    cards->addWidget(statCard(tr("Rules"), &m_statRules));
    cards->addWidget(statCard(tr("Awaiting decision"), &m_statPending));
    cards->addWidget(statCard(tr("Unpackaged"), &m_statUnpackaged));
    layout->addLayout(cards);

    m_healthView = new QTextBrowser;
    m_healthView->setOpenExternalLinks(false);
    m_healthView->setFrameShape(QFrame::NoFrame);
    m_healthView->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_healthView->setMinimumHeight(210);
    m_healthView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    m_healthView->setStyleSheet(
        QStringLiteral("QTextBrowser { background: %1; border: 1px solid %2;"
                       " border-radius: 11px; padding: 14px; }")
            .arg(Theme::surface().name(), Theme::border().name()));
    layout->addWidget(m_healthView);
    layout->addStretch();

    return page;
}

void MainWindow::updateDetail()
{
    const QModelIndex current = m_connectionTable->currentIndex();
    if (!current.isValid()) {
        m_detail->setText(tr("Select a connection to see the binary behind it."));
        m_createRule->setEnabled(false);
        return;
    }
    m_createRule->setEnabled(true);
    const int row = m_connectionFilter->mapToSource(current).row();
    if (row < 0 || row >= m_connectionModel->rowCount())
        return;
    const Connection &c = m_connectionModel->connectionAt(row);

    const QString provenance = c.packageId.isEmpty()
        ? tr("<span style='color:%1'>no owning package</span>").arg(Theme::ask().name())
        : tr("<span style='color:%1'>%2</span>").arg(Theme::allow().name(), c.packageId.toHtmlEscaped());

    m_detail->setText(tr("<b>%1</b> &nbsp; %2 &nbsp;·&nbsp; %3 &nbsp;·&nbsp; %4")
                          .arg(c.processName.toHtmlEscaped(),
                               c.processPath.toHtmlEscaped(),
                               provenance,
                               c.target().toHtmlEscaped()));
}

void MainWindow::createRuleForSelection()
{
    const QModelIndex current = m_connectionTable->currentIndex();
    if (!current.isValid())
        return;
    const int row = m_connectionFilter->mapToSource(current).row();
    if (row < 0 || row >= m_connectionModel->rowCount())
        return;

    // The same dialog the prompts use, so scope and TTL behave identically
    // whether a decision was asked for or sought out.
    auto *prompt = new PromptDialog(m_connectionModel->connectionAt(row), this);
    connect(prompt, &PromptDialog::decided, this, &MainWindow::submitDecision);
    prompt->show();
    prompt->raise();
    prompt->activateWindow();
}

void MainWindow::deleteSelectedRule()
{
    const QModelIndex current = m_ruleTable->currentIndex();
    if (!current.isValid())
        return;
    const int row = m_ruleFilter->mapToSource(current).row();
    if (row < 0 || row >= m_ruleModel->rowCount())
        return;
    const Rule rule = m_ruleModel->ruleAt(row);

    const auto answer = QMessageBox::question(
        this, tr("Delete rule"),
        tr("Delete “%1”?\n\nConnections it covered will go back to awaiting a decision.")
            .arg(rule.ruleName),
        QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (answer != QMessageBox::Yes)
        return;

    m_client->deleteRule(rule.ruleId);
}

void MainWindow::captureNow()
{
    m_client->captureHost();
}

void MainWindow::onConnections(const QList<Connection> &connections)
{
    m_connectionModel->setConnections(connections);
    const bool empty = connections.isEmpty();
    m_connectionEmpty->setVisible(empty);
    m_connectionTable->setVisible(!empty);
    int needsReview = 0, unpackaged = 0;
    for (const Connection &c : connections) {
        if (c.verdict == QLatin1String("ask"))
            ++needsReview;
        if (c.trust() != QLatin1String("trusted"))
            ++unpackaged;
    }
    m_counts->setText(tr("%1 loaded   ·   %2 awaiting a decision   ·   %3 unpackaged")
                          .arg(connections.size()).arg(needsReview).arg(unpackaged));
    queuePrompts(connections);
}

void MainWindow::onRules(const QList<Rule> &rules)
{
    m_ruleModel->setRules(rules);
    const bool empty = rules.isEmpty();
    m_ruleEmpty->setVisible(empty);
    m_ruleTable->setVisible(!empty);
    if (empty)
        m_deleteRule->setEnabled(false);
}

void MainWindow::onHealth(const QJsonObject &health)
{
    const QJsonObject counts = health.value(QStringLiteral("counts")).toObject();
    const QJsonObject bootstrap = health.value(QStringLiteral("bootstrap")).toObject();

    QString html = QStringLiteral("<style>td{padding:3px 14px 3px 0}</style><table>");
    const auto row = [&html](const QString &label, const QString &value) {
        html += QStringLiteral("<tr><td style='color:%1'>%2</td><td><b>%3</b></td></tr>")
                    .arg(Theme::textDim().name(), escape(label), escape(value));
    };
    m_statConnections->setText(QString::number(counts.value(QStringLiteral("connections")).toInt()));
    m_statRules->setText(QString::number(counts.value(QStringLiteral("rules")).toInt()));
    if (m_statPending && counts.contains(QStringLiteral("awaiting_decision")))
        m_statPending->setText(QString::number(counts.value(QStringLiteral("awaiting_decision")).toInt()));
    if (m_statUnpackaged && counts.contains(QStringLiteral("unpackaged")))
        m_statUnpackaged->setText(QString::number(counts.value(QStringLiteral("unpackaged")).toInt()));

    row(tr("Status"), health.value(QStringLiteral("status")).toString());
    row(tr("Database"), bootstrap.value(QStringLiteral("db_path")).toString());
    html += QStringLiteral("</table><br><b>") + tr("Enforcement backends") + QStringLiteral("</b><table>");

    int runnable = 0;
    const QJsonArray backends = health.value(QStringLiteral("enforcement_capabilities")).toArray();
    for (const QJsonValue &value : backends) {
        const QJsonObject backend = value.toObject();
        const bool isRunnable = backend.value(QStringLiteral("runnable")).toBool();
        const bool nativeOn = backend.value(QStringLiteral("native_execution_enabled")).toBool();
        runnable += isRunnable ? 1 : 0;

        QStringList missing;
        for (const QJsonValue &binary : backend.value(QStringLiteral("missing_binaries")).toArray())
            missing << binary.toString();

        // Three distinct states. Reporting "missing:" with an empty list, as
        // this did, hides the common case: every tool is present and the only
        // thing stopping enforcement is that native execution is switched off.
        QString state;
        QColor colour;
        if (!missing.isEmpty()) {
            state = tr("missing %1").arg(missing.join(QStringLiteral(", ")));
            colour = Theme::deny();
        } else if (!nativeOn) {
            state = tr("tools present · native execution off");
            colour = Theme::ask();
        } else {
            state = tr("ready to enforce");
            colour = Theme::allow();
        }

        html += QStringLiteral("<tr><td style='color:%1'>%2</td><td style='color:%3'>%4</td></tr>")
                    .arg(Theme::textDim().name(), escape(backend.value(QStringLiteral("backend")).toString()),
                         colour.name(), escape(state));
    }
    html += QStringLiteral("</table>");
    if (runnable == 0) {
        html += QStringLiteral("<br><span style='color:%1'>%2</span>")
                    .arg(Theme::textDim().name(),
                         tr("Egret is observing only. Set EGRET_ENABLE_NATIVE_EXECUTION=1 "
                            "to let rules reach the host firewall."));
    }
    m_healthView->setHtml(html);

    m_backendState->setText(tr("%1/%2 backends runnable").arg(runnable).arg(backends.size()));
}

void MainWindow::onError(const QString &message)
{
    m_counts->setText(tr("Backend unreachable — %1").arg(message));
    m_backendState->clear();
}

void MainWindow::queuePrompts(const QList<Connection> &connections)
{
    // Prompting is opt-in. A fresh host has dozens of undecided connections, and
    // asking about all of them at once makes the desktop unusable.
    if (!m_promptsEnabled)
        return;

    QSet<QString> queuedProcesses;
    for (const Connection &pending : std::as_const(m_pending))
        queuedProcesses.insert(pending.processName);

    for (const Connection &connection : connections) {
        if (m_pending.size() >= kMaxPendingPrompts)
            break;
        if (connection.verdict != QLatin1String("ask"))
            continue;
        // One prompt per process, not per destination: a browser touches dozens
        // of addresses and they are all the same decision to the user.
        if (m_processDecided.contains(connection.processName)
            || queuedProcesses.contains(connection.processName))
            continue;
        queuedProcesses.insert(connection.processName);
        m_pending.enqueue(connection);
    }
    drainPrompts();
}

void MainWindow::drainPrompts()
{
    if (!m_openPrompt.isNull() || m_pending.isEmpty())
        return;

    const Connection connection = m_pending.dequeue();
    auto *prompt = new PromptDialog(connection, this);
    m_openPrompt = prompt;

    connect(prompt, &PromptDialog::decided, this, &MainWindow::submitDecision);
    connect(prompt, &QDialog::finished, this, [this](int result) {
        // Dismissing without choosing means "not now": stop asking until the
        // user re-arms prompting, rather than immediately opening the next one.
        if (result != QDialog::Accepted) {
            m_pending.clear();
            setPromptsEnabled(false);
            return;
        }
        // A cooldown guarantees the desktop stays usable even with a long queue.
        QTimer::singleShot(kPromptCooldownMs, this, &MainWindow::drainPrompts);
    });

    prompt->show();
    prompt->raise();
    prompt->activateWindow();
}

void MainWindow::setPromptsEnabled(bool enabled)
{
    m_promptsEnabled = enabled;
    if (!enabled)
        m_pending.clear();
    if (m_promptToggle->isChecked() != enabled)
        m_promptToggle->setChecked(enabled);
}

void MainWindow::submitDecision(const Connection &connection, const QString &action, int ttlSeconds,
                                ApiClient::RuleScope scope)
{
    m_decided.insert(connection.key());
    if (scope == ApiClient::RuleScope::Process) {
        // The answer covers everything this process does, so drop any prompts
        // already queued for it rather than asking again per destination.
        m_processDecided.insert(connection.processName);
        QQueue<Connection> keep;
        for (const Connection &queued : std::as_const(m_pending)) {
            if (queued.processName != connection.processName)
                keep.enqueue(queued);
        }
        m_pending = keep;
    }
    m_client->createRule(connection, action, ttlSeconds, scope);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // Hide to tray only when this app actually created one. Testing the
    // system-wide availability instead would strand the user with --no-tray:
    // the window would hide with nothing left to restore or quit it.
    if (m_hasTray) {
        hide();
        event->ignore();
        return;
    }
    QMainWindow::closeEvent(event);
}
