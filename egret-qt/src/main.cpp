#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QProcessEnvironment>

#include "ApiClient.h"
#include "AppIcon.h"
#include "MainWindow.h"
#include "Theme.h"
#include "TrayIcon.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Egret"));
    QApplication::setApplicationVersion(QStringLiteral("12.0.0"));
    QApplication::setOrganizationName(QStringLiteral("Egret"));
    QApplication::setDesktopFileName(QStringLiteral("dev.egret.Native"));
    // Window, task switcher, and Alt-Tab all take the icon from here.
    QApplication::setWindowIcon(AppIcon::icon());

    const QString defaultUrl = QProcessEnvironment::systemEnvironment().value(
        QStringLiteral("EGRET_URL"), QStringLiteral("http://127.0.0.1:8000"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Egret native client"));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption urlOption(QStringList{QStringLiteral("u"), QStringLiteral("base-url")},
                                 QStringLiteral("Backend base URL."), QStringLiteral("url"), defaultUrl);
    QCommandLineOption pollOption(QStringList{QStringLiteral("p"), QStringLiteral("poll")},
                                  QStringLiteral("Seconds between host captures."), QStringLiteral("seconds"),
                                  QStringLiteral("10"));
    QCommandLineOption noTrayOption(QStringLiteral("no-tray"), QStringLiteral("Run without a tray icon."));
    QCommandLineOption exportIconsOption(
        QStringLiteral("export-icons"),
        QStringLiteral("Write PNG icons to <dir> and exit. For packaging against icon "
                       "themes that do not read SVG."),
        QStringLiteral("dir"));
    parser.addOption(urlOption);
    parser.addOption(pollOption);
    parser.addOption(noTrayOption);
    parser.addOption(exportIconsOption);
    parser.process(app);

    if (parser.isSet(exportIconsOption)) {
        const QString target = parser.value(exportIconsOption);
        if (!QDir().mkpath(target)) {
            fprintf(stderr, "cannot create %s\n", qPrintable(target));
            return 1;
        }
        for (int size : {16, 22, 24, 32, 48, 64, 128, 256}) {
            const QString path =
                QStringLiteral("%1/dev.egret.Native-%2.png").arg(target).arg(size);
            if (!AppIcon::pixmap(size).save(path, "PNG")) {
                fprintf(stderr, "cannot write %s\n", qPrintable(path));
                return 1;
            }
        }
        return 0;
    }

    bool pollOk = false;
    const int pollSeconds = parser.value(pollOption).toInt(&pollOk);

    Theme::apply(app);

    auto *client = new ApiClient(parser.value(urlOption), &app);
    auto *window = new MainWindow(client, pollOk && pollSeconds > 0 ? pollSeconds : 10);

    const bool wantTray = !parser.isSet(noTrayOption) && QSystemTrayIcon::isSystemTrayAvailable();
    if (wantTray) {
        auto *tray = new TrayIcon(window, &app);
        tray->show();
        window->setHasTray(true);
    } else {
        // Without a tray there is nowhere to restore from, so closing must exit.
        QApplication::setQuitOnLastWindowClosed(true);
    }

    window->show();
    return app.exec();
}
