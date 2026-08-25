#pragma once

#include <QSystemTrayIcon>

class MainWindow;

/// Tray presence with a Show / Capture / Quit menu.
///
/// Unlike the GTK build this needs no helper process: QSystemTrayIcon speaks
/// StatusNotifierItem directly from the same process as the main window.
class TrayIcon : public QSystemTrayIcon {
    Q_OBJECT

public:
    explicit TrayIcon(MainWindow *window, QObject *parent = nullptr);

private:
    MainWindow *m_window;
};
