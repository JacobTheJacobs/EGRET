#include "Theme.h"

#include <QApplication>
#include <QPalette>
#include <QStyleFactory>

namespace Theme {

QColor verdictColor(const QString &verdict)
{
    if (verdict == QLatin1String("allow"))
        return allow();
    if (verdict == QLatin1String("deny"))
        return deny();
    if (verdict == QLatin1String("ask"))
        return ask();
    return textDim();
}

QColor trustColor(const QString &trust)
{
    if (trust == QLatin1String("trusted"))
        return allow();
    if (trust == QLatin1String("unsigned"))
        return ask();
    return textDim();
}

void apply(QApplication &app)
{
    app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    palette.setColor(QPalette::Window, background());
    palette.setColor(QPalette::WindowText, text());
    palette.setColor(QPalette::Base, background());
    palette.setColor(QPalette::AlternateBase, surface());
    palette.setColor(QPalette::Text, text());
    palette.setColor(QPalette::Button, surface());
    palette.setColor(QPalette::ButtonText, text());
    palette.setColor(QPalette::Highlight, accent());
    palette.setColor(QPalette::HighlightedText, background());
    palette.setColor(QPalette::ToolTipBase, surface());
    palette.setColor(QPalette::ToolTipText, text());
    palette.setColor(QPalette::Mid, textDim());
    palette.setColor(QPalette::PlaceholderText, textDim());
    app.setPalette(palette);

    app.setStyleSheet(QStringLiteral(R"(
        QWidget { font-size: 13px; }

        #Sidebar {
            background: %2;
            border-right: 1px solid %3;
        }
        #Sidebar QPushButton {
            background: transparent;
            border: none;
            border-radius: 8px;
            color: %5;
            padding: 9px 14px;
            text-align: left;
        }
        #Sidebar QPushButton:hover { background: rgba(148,163,184,0.12); color: %4; }
        #Sidebar QPushButton:checked { background: %6; color: %1; font-weight: 600; }

        #Brand { color: %6; font-size: 15px; font-weight: 700; padding: 14px; }
        #PageTitle { font-size: 20px; font-weight: 600; }

        QLineEdit {
            background: %2;
            border: 1px solid %3;
            border-radius: 8px;
            padding: 7px 11px;
            selection-background-color: %6;
        }
        QLineEdit:focus { border-color: %6; }

        QPushButton {
            background: %2;
            border: 1px solid %3;
            border-radius: 8px;
            padding: 7px 14px;
        }
        QPushButton:hover { border-color: %6; }
        QPushButton:default { background: %6; color: %1; border-color: %6; font-weight: 600; }
        QPushButton#Danger { background: #b91c1c; border-color: #b91c1c; color: #fff; font-weight: 600; }

        QPushButton#Chip {
            background: transparent;
            border: 1px solid %3;
            border-radius: 13px;
            color: %5;
            padding: 5px 13px;
        }
        QPushButton#Chip:hover { color: %4; border-color: %5; }
        QPushButton#Chip:checked {
            background: rgba(56,189,248,0.16);
            border-color: %6;
            color: %6;
            font-weight: 600;
        }

        QCheckBox { color: %5; spacing: 8px; padding: 4px 2px; }
        QCheckBox:hover { color: %4; }
        QCheckBox::indicator {
            width: 15px; height: 15px;
            border: 1px solid %5;
            border-radius: 4px;
            background: %1;
        }
        QCheckBox::indicator:hover { border-color: %6; }
        QCheckBox::indicator:checked { background: %6; border-color: %6; }

        QWidget#DetailBar {
            background: %2;
            border: 1px solid %3;
            border-radius: 9px;
            color: %5;
            padding: 9px 12px;
        }

        QFrame#Card {
            background: %2;
            border: 1px solid %3;
            border-radius: 11px;
        }
        QLabel#CardValue { font-size: 21px; font-weight: 600; color: %4; }
        QLabel#CardLabel { color: %5; font-size: 11px;
                           text-transform: uppercase; letter-spacing: 1px; }

        QTableView {
            background: %1;
            alternate-background-color: rgba(148,163,184,0.05);
            border: 1px solid %3;
            border-radius: 10px;
            gridline-color: transparent;
            selection-background-color: rgba(56,189,248,0.18);
            selection-color: %4;
        }
        QTableView::item { padding: 7px 6px; border: none; }
        QHeaderView::section {
            background: %2;
            border: none;
            border-bottom: 1px solid %3;
            color: %5;
            font-weight: 600;
            padding: 8px 6px;
        }

        QStatusBar { color: %5; border-top: 1px solid %3; }
        QStatusBar::item { border: none; }

        QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
        QScrollBar::handle:vertical { background: %3; border-radius: 5px; min-height: 28px; }
        QScrollBar::handle:vertical:hover { background: %5; }
        QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
        QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
    )")
                           .arg(background().name(), surface().name(), border().name(), text().name(),
                                textDim().name(), accent().name()));
}

} // namespace Theme
