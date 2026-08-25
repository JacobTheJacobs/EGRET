#pragma once

#include <QStyledItemDelegate>

/// Paints a short status word as a filled pill.
///
/// Colour alone is not enough — a pill gives the value a shape and a boundary,
/// so "unsigned" reads as a distinct state rather than differently coloured
/// text, and stays legible for viewers who cannot separate red from green.
class BadgeDelegate : public QStyledItemDelegate {
    Q_OBJECT

public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};
