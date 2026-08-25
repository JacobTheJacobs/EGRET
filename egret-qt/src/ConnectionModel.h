#pragma once

#include <QAbstractTableModel>
#include <QList>
#include <QSortFilterProxyModel>

#include "ApiClient.h"

/// Table model over captured connections.
///
/// Sorting and text filtering are handled by a QSortFilterProxyModel on top of
/// this, so the model itself stays a thin, replaceable view of the API payload.
class ConnectionModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ProcessColumn,
        TargetColumn,
        PortColumn,
        ProtocolColumn,
        TrustColumn,
        VerdictColumn,
        ColumnCount,
    };

    /// Role exposing the underlying row index so views can recover the Connection.
    static constexpr int ConnectionRole = Qt::UserRole + 1;
    /// Raw verdict and trust words, so filtering never depends on display text.
    static constexpr int VerdictRole = Qt::UserRole + 2;
    static constexpr int TrustRole = Qt::UserRole + 3;

    explicit ConnectionModel(QObject *parent = nullptr);

    void setConnections(const QList<Connection> &connections);
    const Connection &connectionAt(int row) const { return m_connections.at(row); }

    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    QList<Connection> m_connections;
};

/// Text search plus a one-click category, so the common questions -- what needs
/// a decision, what is unpackaged -- are a button rather than a typed query.
class ConnectionFilterProxy : public QSortFilterProxyModel {
    Q_OBJECT

public:
    enum class Category { All, NeedsReview, Unsigned, Allowed, Denied };

    using QSortFilterProxyModel::QSortFilterProxyModel;

    void setCategory(Category category);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    Category m_category = Category::All;
};

/// Table model over policy rules.
class RuleModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column { NameColumn, ProcessColumn, TargetColumn, ExpiresColumn, ActionColumn, ColumnCount };

    explicit RuleModel(QObject *parent = nullptr);

    void setRules(const QList<Rule> &rules);
    const Rule &ruleAt(int row) const { return m_rules.at(row); }

    int rowCount(const QModelIndex &parent = {}) const override;
    int columnCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    QList<Rule> m_rules;
};
