#pragma once

#include <QColor>
#include <QString>

class QApplication;

/// Centralised dark palette and stylesheet.
///
/// Colours mirror the web UI's slate/sky scheme so the two clients read as one
/// product. Verdict colours are shared with the table model and the prompt.
namespace Theme {

inline const QColor background() { return QColor(0x0f, 0x17, 0x2a); }
inline const QColor surface() { return QColor(0x1e, 0x29, 0x3b); }
inline const QColor border() { return QColor(0x33, 0x41, 0x55); }
inline const QColor text() { return QColor(0xe2, 0xe8, 0xf0); }
inline const QColor textDim() { return QColor(0x94, 0xa3, 0xb8); }
inline const QColor accent() { return QColor(0x38, 0xbd, 0xf8); }

inline const QColor allow() { return QColor(0x4a, 0xde, 0x80); }
inline const QColor deny() { return QColor(0xf8, 0x71, 0x71); }
inline const QColor ask() { return QColor(0xfb, 0xbf, 0x24); }

/// Colour for a verdict string; falls back to dim text for unknown values.
QColor verdictColor(const QString &verdict);

/// Colour for a trust word: packaged binaries read calm, unpackaged read hot.
QColor trustColor(const QString &trust);

/// Apply the Fusion base palette and stylesheet to the whole application.
void apply(QApplication &app);

} // namespace Theme
