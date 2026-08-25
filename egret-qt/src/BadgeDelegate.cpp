#include "BadgeDelegate.h"

#include <QApplication>
#include <QFontMetrics>
#include <QStyle>
#include <QPainter>

#include "Theme.h"

namespace {

constexpr int kPaddingX = 9;
constexpr int kPaddingY = 3;
constexpr qreal kRadius = 8.0;

/// Slightly smaller and bold, derived safely.
///
/// The stylesheet sets font-size in pixels, so pointSizeF() reports -1 and
/// arithmetic on it yields an invalid size that Qt warns about on every paint.
QFont badgeFont(const QFont &base)
{
    QFont font(base);
    if (font.pointSizeF() > 0.0)
        font.setPointSizeF(font.pointSizeF() - 0.5);
    else if (font.pixelSize() > 1)
        font.setPixelSize(font.pixelSize() - 1);
    font.setBold(true);
    return font;
}

} // namespace

void BadgeDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const
{
    const QString text = index.data(Qt::DisplayRole).toString();
    if (text.isEmpty()) {
        QStyledItemDelegate::paint(painter, option, index);
        return;
    }

    // Draw the row background through the style rather than calling the base
    // paint: QStyledItemDelegate::paint re-runs initStyleOption internally, so
    // clearing opt.text there has no effect and the label is painted twice.
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);
    opt.text.clear();
    const QWidget *widget = opt.widget;
    QStyle *style = widget ? widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, widget);

    const QColor accent = index.data(Qt::ForegroundRole).value<QColor>();
    const QFont font = badgeFont(option.font);
    const QFontMetrics metrics(font);
    const int width = metrics.horizontalAdvance(text) + kPaddingX * 2;
    const int height = metrics.height() + kPaddingY * 2;

    QRect pill(0, 0, width, height);
    pill.moveCenter(option.rect.center());
    pill.moveLeft(option.rect.left() + 4);

    painter->save();
    painter->setRenderHint(QPainter::Antialiasing);

    QColor fill = accent;
    fill.setAlpha(38);
    painter->setPen(Qt::NoPen);
    painter->setBrush(fill);
    painter->drawRoundedRect(pill, kRadius, kRadius);

    painter->setFont(font);
    painter->setPen(accent);
    painter->drawText(pill, Qt::AlignCenter, text);
    painter->restore();
}

QSize BadgeDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    const QString text = index.data(Qt::DisplayRole).toString();
    if (text.isEmpty())
        return QStyledItemDelegate::sizeHint(option, index);

    const QFontMetrics metrics(badgeFont(option.font));
    return {metrics.horizontalAdvance(text) + kPaddingX * 2 + 12, metrics.height() + kPaddingY * 2 + 8};
}
