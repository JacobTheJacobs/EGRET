cmake_minimum_required(VERSION 3.16)
project(egret VERSION 12.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

include(GNUInstallDirs)

find_package(Qt6 REQUIRED COMPONENTS Widgets Network Svg)

add_executable(egret
    src/main.cpp
    src/ApiClient.cpp
    src/AppIcon.cpp
    src/BadgeDelegate.cpp
    src/ConnectionModel.cpp
    src/MainWindow.cpp
    src/PromptDialog.cpp
    src/Theme.cpp
    src/TrayIcon.cpp
    resources/egret.qrc
)

target_include_directories(egret PRIVATE src)
target_link_libraries(egret PRIVATE Qt6::Widgets Qt6::Network Qt6::Svg)

install(TARGETS egret RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# The same SVG the binary embeds is installed into the icon theme, so the
# launcher entry and the running application always show one identical mark.
install(FILES resources/dev.egret.Native.svg
    DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps)
install(FILES resources/dev.egret.Native.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
