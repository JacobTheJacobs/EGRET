#pragma once

#include <QIcon>
#include <QPixmap>

/// The Egret mark, drawn in code so the binary ships without asset files.
///
/// The silhouette is a head, dagger bill, and long S-curved neck — the parts of
/// an egret that stay legible once a tray icon is down to 16 px. A whole bird
/// turns to mush at that size.
namespace AppIcon {

/// Render the mark at one edge length, in pixels.
QPixmap pixmap(int size);

/// A multi-resolution icon for the tray, window, and task switcher.
QIcon icon();

} // namespace AppIcon
