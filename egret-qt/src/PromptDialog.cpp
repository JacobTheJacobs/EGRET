#include "PromptDialog.h"

#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include "Theme.h"

namespace {

constexpr int kTemporaryTtlSeconds = 300;

QString targetLine(const Connection &connection)
{
    QString line = connection.target();
    if (connection.port > 0)
        line += QStringLiteral(":%1").arg(connection.port);
    if (!connection.protocol.isEmpty())
        line += QStringLiteral("  ·  %1").arg(connection.protocol);
    return line;
}

} // namespace

PromptDialog::PromptDialog(const Connection &connection, QWidget *parent)
    : QDialog(parent)
    , m_connection(connection)
{
    setWindowTitle(tr("Egret"));
    setWindowFlag(Qt::WindowStaysOnTopHint, true);
    setAttribute(Qt::WA_DeleteOnClose);
    setMinimumWidth(440);

    const bool risky = connection.unsigned_or_unknown();
    const QColor accent = risky ? Theme::ask() : Theme::accent();

    // Coloured risk strip down the left edge.
    auto *strip = new QFrame;
    strip->setFixedWidth(4);
    strip->setStyleSheet(QStringLiteral("background: %1; border-radius: 2px;").arg(accent.name()));

    auto *body = new QVBoxLayout;
    body->setSpacing(9);

    auto *headline = new QLabel(tr("<b>%1</b> wants to connect").arg(connection.processName.toHtmlEscaped()));
    headline->setTextFormat(Qt::RichText);
    headline->setWordWrap(true);
    QFont headlineFont = headline->font();
    headlineFont.setPointSizeF(headlineFont.pointSizeF() + 3.0);
    headline->setFont(headlineFont);
    body->addWidget(headline);

    auto *target = new QLabel(targetLine(connection));
    target->setTextInteractionFlags(Qt::TextSelectableByMouse);
    target->setWordWrap(true);
    target->setStyleSheet(QStringLiteral("color: %1; font-family: monospace; font-size: 14px;").arg(accent.name()));
    body->addWidget(target);

    if (!connection.domain.isEmpty() && !connection.ip.isEmpty() && connection.domain != connection.ip) {
        auto *resolved = new QLabel(connection.ip);
        resolved->setStyleSheet(QStringLiteral("color: %1; font-family: monospace;").arg(Theme::textDim().name()));
        body->addWidget(resolved);
    }

    auto *path = new QLabel(connection.processPath);
    path->setTextInteractionFlags(Qt::TextSelectableByMouse);
    path->setWordWrap(true);
    path->setStyleSheet(QStringLiteral("color: %1; font-size: 12px;").arg(Theme::textDim().name()));
    body->addWidget(path);

    if (risky) {
        auto *warning = new QLabel(tr("⚠  Unsigned or unverified binary"));
        warning->setStyleSheet(QStringLiteral("color: %1; font-weight: 600; padding-top: 2px;").arg(Theme::ask().name()));
        body->addWidget(warning);
    }

    auto *separator = new QFrame;
    separator->setFrameShape(QFrame::HLine);
    separator->setStyleSheet(QStringLiteral("color: %1;").arg(Theme::border().name()));
    body->addWidget(separator);

    // Scope selector. Address scope re-prompts on every rotating CDN node, so
    // the default is the broadest option that still names something specific.
    auto *scopeRow = new QHBoxLayout;
    auto *scopeLabel = new QLabel(tr("Apply to"));
    scopeLabel->setStyleSheet(QStringLiteral("color: %1;").arg(Theme::textDim().name()));
    scopeRow->addWidget(scopeLabel);

    m_scope = new QComboBox;
    if (connection.hasDomain()) {
        m_scope->addItem(tr("%1 and sub-domains").arg(connection.ruleDomain()),
                         QVariant::fromValue(static_cast<int>(ApiClient::RuleScope::Domain)));
    }
    m_scope->addItem(tr("any destination for %1").arg(connection.processName),
                     QVariant::fromValue(static_cast<int>(ApiClient::RuleScope::Process)));
    m_scope->addItem(tr("only %1:%2").arg(connection.ip).arg(connection.port),
                     QVariant::fromValue(static_cast<int>(ApiClient::RuleScope::Address)));
    m_scope->setCurrentIndex(0);
    scopeRow->addWidget(m_scope, 1);
    body->addLayout(scopeRow);

    auto *buttons = new QGridLayout;
    buttons->setSpacing(7);

    auto *allow = new QPushButton(tr("Allow"));
    allow->setDefault(true);
    allow->setCursor(Qt::PointingHandCursor);

    auto *deny = new QPushButton(tr("Deny"));
    deny->setObjectName(QStringLiteral("Danger"));
    deny->setCursor(Qt::PointingHandCursor);

    auto *allowOnce = new QPushButton(tr("Allow 5 min"));
    auto *denyOnce = new QPushButton(tr("Deny 5 min"));
    allowOnce->setCursor(Qt::PointingHandCursor);
    denyOnce->setCursor(Qt::PointingHandCursor);

    buttons->addWidget(allow, 0, 0);
    buttons->addWidget(deny, 0, 1);
    buttons->addWidget(allowOnce, 1, 0);
    buttons->addWidget(denyOnce, 1, 1);
    body->addLayout(buttons);

    auto *hint = new QLabel(tr("Permanent choices become rules. Timed choices expire after 5 minutes."));
    hint->setWordWrap(true);
    hint->setStyleSheet(QStringLiteral("color: %1; font-size: 11px;").arg(Theme::textDim().name()));
    body->addWidget(hint);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(14, 14, 16, 14);
    layout->setSpacing(14);
    layout->addWidget(strip);
    layout->addLayout(body, 1);

    connect(allow, &QPushButton::clicked, this, [this] { decide(QStringLiteral("allow"), 0); });
    connect(deny, &QPushButton::clicked, this, [this] { decide(QStringLiteral("deny"), 0); });
    connect(allowOnce, &QPushButton::clicked, this,
            [this] { decide(QStringLiteral("allow"), kTemporaryTtlSeconds); });
    connect(denyOnce, &QPushButton::clicked, this,
            [this] { decide(QStringLiteral("deny"), kTemporaryTtlSeconds); });
}

ApiClient::RuleScope PromptDialog::selectedScope() const
{
    return static_cast<ApiClient::RuleScope>(m_scope->currentData().toInt());
}

void PromptDialog::decide(const QString &action, int ttlSeconds)
{
    emit decided(m_connection, action, ttlSeconds, selectedScope());
    accept();
}
