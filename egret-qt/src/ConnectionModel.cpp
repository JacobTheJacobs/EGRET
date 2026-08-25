#include "ConnectionModel.h"

#include <QFont>

#include "Theme.h"

ConnectionModel::ConnectionModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void ConnectionModel::setConnections(const QList<Connection> &connections)
{
    beginResetModel();
    m_connections = connections;
    endResetModel();
}

int ConnectionModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(m_connections.size());
}

int ConnectionModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ConnectionModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_connections.size())
        return {};

    const Connection &connection = m_connections.at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case ProcessColumn:
            return connection.processName;
        case TargetColumn:
            return connection.target();
        case PortColumn:
            return connection.port > 0 ? QVariant(connection.port) : QVariant(QString());
        case ProtocolColumn:
            return connection.protocol;
        case TrustColumn:
            return connection.trust();
        case VerdictColumn:
            return connection.verdict;
        default:
            return {};
        }

    case Qt::ForegroundRole:
        if (index.column() == VerdictColumn)
            return Theme::verdictColor(connection.verdict);
        if (index.column() == TrustColumn)
            return Theme::trustColor(connection.trust());
        if (index.column() == TargetColumn || index.column() == ProtocolColumn)
            return Theme::textDim();
        return {};

    case Qt::FontRole:
        if (index.column() == ProcessColumn || index.column() == VerdictColumn) {
            QFont font;
            font.setBold(true);
            return font;
        }
        return {};

    case Qt::TextAlignmentRole:
        if (index.column() == PortColumn)
            return QVariant(Qt::AlignRight | Qt::AlignVCenter);
        return QVariant(Qt::AlignLeft | Qt::AlignVCenter);

    case Qt::ToolTipRole:
        if (index.column() == TrustColumn) {
            return connection.packageId.isEmpty()
                       ? tr("No package owns this binary — it did not arrive through a signed repository.")
                       : tr("Provided by package: %1").arg(connection.packageId);
        }
        return QStringLiteral("%1\n%2").arg(connection.processPath, connection.ip);

    case ConnectionRole:
        return index.row();

    case VerdictRole:
        return connection.verdict;

    case TrustRole:
        return connection.trust();

    default:
        return {};
    }
}

QVariant ConnectionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};
    switch (section) {
    case ProcessColumn:
        return tr("Process");
    case TargetColumn:
        return tr("Destination");
    case PortColumn:
        return tr("Port");
    case ProtocolColumn:
        return tr("Protocol");
    case TrustColumn:
        return tr("Trust");
    case VerdictColumn:
        return tr("Verdict");
    default:
        return {};
    }
}

void ConnectionFilterProxy::setCategory(Category category)
{
    if (m_category == category)
        return;
    m_category = category;
    invalidateFilter();
}

bool ConnectionFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (!QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent))
        return false;
    if (m_category == Category::All)
        return true;

    const QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);
    const QString verdict = index.data(ConnectionModel::VerdictRole).toString();
    const QString trust = index.data(ConnectionModel::TrustRole).toString();

    switch (m_category) {
    case Category::NeedsReview:
        return verdict == QLatin1String("ask");
    case Category::Unsigned:
        return trust != QLatin1String("trusted");
    case Category::Allowed:
        return verdict == QLatin1String("allow");
    case Category::Denied:
        return verdict == QLatin1String("deny");
    case Category::All:
        break;
    }
    return true;
}

namespace {

/// Plain words for a rule's lifetime; expired rules are called out because they
/// linger in the list until maintenance runs even though policy ignores them.
QString _expiryText(const Rule &rule)
{
    // Maintenance disables a lapsed rule rather than deleting it, so a rule can
    // still be listed while no longer applying. Say so plainly.
    if (!rule.enabled)
        return QObject::tr("expired");
    const QDateTime end = rule.expiresAt();
    if (!end.isValid())
        return QObject::tr("never");
    const qint64 seconds = QDateTime::currentDateTimeUtc().secsTo(end);
    if (seconds <= 0)
        return QObject::tr("expired");
    if (seconds < 60)
        return QObject::tr("in %1s").arg(seconds);
    if (seconds < 3600)
        return QObject::tr("in %1m").arg(seconds / 60);
    return QObject::tr("in %1h").arg(seconds / 3600);
}

} // namespace

RuleModel::RuleModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void RuleModel::setRules(const QList<Rule> &rules)
{
    beginResetModel();
    m_rules = rules;
    endResetModel();
}

int RuleModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(m_rules.size());
}

int RuleModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant RuleModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_rules.size())
        return {};

    const Rule &rule = m_rules.at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        switch (index.column()) {
        case NameColumn:
            return rule.ruleName;
        case ProcessColumn:
            return rule.processName;
        case TargetColumn:
            return rule.target;
        case ExpiresColumn:
            return _expiryText(rule);
        case ActionColumn:
            return rule.action;
        default:
            return {};
        }

    case Qt::ForegroundRole:
    {
        const bool inactive = !rule.enabled || rule.hasLapsed();
        if (index.column() == ActionColumn)
            return inactive ? Theme::textDim() : Theme::verdictColor(rule.action);
        if (index.column() == ExpiresColumn)
            return inactive ? Theme::deny() : Theme::textDim();
        if (inactive)
            return Theme::textDim();
    }
        if (index.column() == TargetColumn)
            return Theme::textDim();
        return {};

    case Qt::FontRole:
        if (index.column() == ActionColumn) {
            QFont font;
            font.setBold(true);
            return font;
        }
        return {};

    default:
        return {};
    }
}

QVariant RuleModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return {};
    switch (section) {
    case NameColumn:
        return tr("Rule");
    case ProcessColumn:
        return tr("Process");
    case TargetColumn:
        return tr("Target");
    case ExpiresColumn:
        return tr("Expires");
    case ActionColumn:
        return tr("Action");
    default:
        return {};
    }
}
