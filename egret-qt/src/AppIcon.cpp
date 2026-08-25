#include "AppIcon.h"

#include <QPainter>
#include <QSvgRenderer>

namespace {

//: Single source of truth for the mark. The same file is installed into the
//: icon theme, so the tray, the window, and the launcher cannot drift apart.
constexpr const char *kIconResource = ":/icons/dev.egret.Native.svg";

//: Sizes a desktop environment is likely to ask for.
constexpr int kSizes[] = {16, 22, 24, 32, 48, 64, 128, 256};

} // namespace

namespace AppIcon {

QPixmap pixmap(int size)
{
    QPixmap target(size, size);
    target.fill(Qt::transparent);

    QSvgRenderer renderer{QString::fromLatin1(kIconResource)};
    if (!renderer.isValid())
        return target;

    QPainter painter(&target);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    renderer.render(&painter);
    return target;
}

QIcon icon()
{
    QIcon result;
    for (int size : kSizes)
        result.addPixmap(pixmap(size));
    return result;
}

} // namespace AppIcon
