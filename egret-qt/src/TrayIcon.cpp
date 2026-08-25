#include "TrayIcon.h"

#include <QAction>
#include <QApplication>
#include <QMenu>

#include "AppIcon.h"
#include "MainWindow.h"

TrayIcon::TrayIcon(MainWindow *window, QObject *parent)
    : QSystemTrayIcon(parent)
    , m_window(window)
{
    setIcon(AppIcon::icon());
    setToolTip(QObject::tr("Egret"));

    auto *menu = new QMenu;
    QAction *show = menu->addAction(QObject::tr("Show Egret"));
    QAction *capture = menu->addAction(QObject::tr("Capture now"));
    menu->addSeparator();
    QAction *quit = menu->addAction(QObject::tr("Quit"));
    setContextMenu(menu);

    connect(show, &QAction::triggered, this, [this] {
        m_window->show();
        m_window->raise();
        m_window->activateWindow();
    });
    connect(capture, &QAction::triggered, m_window, &MainWindow::captureNow);
    connect(quit, &QAction::triggered, qApp, &QApplication::quit);

    connect(this, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason != QSystemTrayIcon::Trigger)
            return;
        if (m_window->isVisible()) {
            m_window->hide();
        } else {
            m_window->show();
            m_window->raise();
            m_window->activateWindow();
        }
    });
}
