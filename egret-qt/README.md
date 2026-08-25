# Egret — native Qt6 client

Compiled C++ desktop client for the Egret backend. Ships as a single ELF
binary with no interpreter or runtime.

It talks to the backend over the same REST API the web UI uses and never opens
the SQLite database directly.

## Build

```bash
sudo apt install -y qt6-base-dev libqt6svg6-dev    # one-time
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/egret
```

## Install

```bash
sudo cmake --install build --prefix /usr/local
```

Installs three files:

| Path | Purpose |
| --- | --- |
| `bin/egret` | the binary |
| `share/applications/dev.egret.Native.desktop` | launcher entry |
| `share/icons/hicolor/scalable/apps/dev.egret.Native.svg` | themed icon |

Run `update-desktop-database` and `gtk-update-icon-cache` afterwards if your
desktop does not pick the entry up immediately.

## Run

```bash
./build/egret                          # defaults to http://127.0.0.1:8000
./build/egret --base-url http://host:8000 --poll 15
./build/egret --no-tray
```

`EGRET_URL` sets the default backend if `--base-url` is omitted.

The backend must be running:

```bash
cd ../src/avwork && uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## What it adds over the web UI

*   **Tray presence.** `QSystemTrayIcon` speaks StatusNotifierItem from the main
    process — no helper subprocess, unlike the GTK build in `app/native/`.
    Closing the window hides to tray; left-click toggles.
*   **Always-on-top prompts.** Connections the policy engine returns an `ask`
    verdict for raise a prompt over every other window. Allow/Deny create a
    permanent rule; the timed variants create one with a 300s TTL.

Prompts are queued one at a time and de-duplicated on
`process|destination|port`, so a busy host cannot produce a prompt storm.

## Icon

The mark is a single SVG in `resources/`, embedded in the binary as a Qt
resource *and* installed into the icon theme, so the tray, the window, and the
launcher can never drift apart. For packaging against themes that will not read
SVG, export PNGs:

```bash
./build/egret --export-icons /tmp/icons     # 16 through 256 px
```

## Layout

| File | Role |
| --- | --- |
| `ApiClient.*` | async REST client, JSON → `Connection`/`Rule` structs |
| `ConnectionModel.*` | table models behind sortable, filterable views |
| `MainWindow.*` | sidebar shell, live search, prompt queue |
| `PromptDialog.*` | always-on-top Allow/Deny prompt |
| `TrayIcon.*` | tray icon and menu |
| `AppIcon.*` | renders the shared SVG mark at any size |
| `Theme.*` | palette and stylesheet, matching the web UI's slate/sky scheme |

## Notes

*   Qt6 6.2 (Ubuntu 22.04) is the floor — no Qt 6.4+ APIs are used.
*   The tray icon is drawn with `QPainter` at startup, so the binary needs no
    icon assets or resource file.
