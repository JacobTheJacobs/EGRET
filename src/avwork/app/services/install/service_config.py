from __future__ import annotations

import html
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ServiceConfigPaths:
    systemd_unit: Path
    launchd_plist: Path
    windows_script: Path

    def to_dict(self) -> dict:
        return {
            'systemd_unit': str(self.systemd_unit),
            'launchd_plist': str(self.launchd_plist),
            'windows_script': str(self.windows_script),
        }


@dataclass(frozen=True)
class ServiceConfigInput:
    app_dir: Path
    data_dir: Path
    db_path: Path
    content_dir: Path
    backend_state_dir: Path
    host: str = '127.0.0.1'
    port: int = 8000
    python_executable: str = sys.executable
    ingest_token: str | None = None

    @property
    def env(self) -> dict[str, str]:
        values = {
            'EGRET_DB_PATH': str(self.db_path),
            'EGRET_CONTENT_DIR': str(self.content_dir),
            'EGRET_BACKEND_STATE_DIR': str(self.backend_state_dir),
        }
        if self.ingest_token is not None:
            values['EGRET_INGEST_TOKEN'] = self.ingest_token
        return values


def render_systemd_unit(config: ServiceConfigInput) -> str:
    env_lines = '\n'.join(f'Environment="{key}={value}"' for key, value in config.env.items())
    exec_start = ' '.join(
        shlex.quote(part)
        for part in (
            config.python_executable,
            '-m',
            'uvicorn',
            'app.main:app',
            '--host',
            config.host,
            '--port',
            str(config.port),
        )
    )
    return f"""[Unit]
Description=Egret
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={config.app_dir}
{env_lines}
ExecStart={exec_start}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def render_launchd_plist(config: ServiceConfigInput) -> str:
    args = [
        config.python_executable,
        '-m',
        'uvicorn',
        'app.main:app',
        '--host',
        config.host,
        '--port',
        str(config.port),
    ]
    arg_xml = '\n'.join(f'    <string>{html.escape(arg)}</string>' for arg in args)
    env_xml = '\n'.join(f'    <key>{key}</key><string>{html.escape(value)}</string>' for key, value in config.env.items())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.egret.agent</string>
  <key>WorkingDirectory</key><string>{html.escape(str(config.app_dir))}</string>
  <key>ProgramArguments</key>
  <array>
{arg_xml}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
{env_xml}
  </dict>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"""


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_windows_service_script(config: ServiceConfigInput) -> str:
    arguments = ' '.join(
        [
            '-m',
            'uvicorn',
            'app.main:app',
            '--host',
            config.host,
            '--port',
            str(config.port),
        ]
    )
    env_lines = '\n'.join(f'[Environment]::SetEnvironmentVariable({_ps_quote(key)}, {_ps_quote(value)}, "Machine")' for key, value in config.env.items())
    return f"""$ErrorActionPreference = "Stop"
$ServiceName = "Egret"
$Python = {_ps_quote(config.python_executable)}
$Arguments = {_ps_quote(arguments)}
$WorkingDirectory = {_ps_quote(str(config.app_dir))}

{env_lines}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {{
  Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
  sc.exe delete $ServiceName | Out-Null
}}

New-Service -Name $ServiceName -DisplayName "Egret" -StartupType Automatic -BinaryPathName "`"$Python`" $Arguments"
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$ServiceName" -Name "AppDirectory" -Value $WorkingDirectory
Write-Host "Installed Egret Windows service definition."
"""


def write_service_configs(config: ServiceConfigInput, output_dir: Path) -> ServiceConfigPaths:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = ServiceConfigPaths(
        systemd_unit=output_dir / 'egret.service',
        launchd_plist=output_dir / 'com.egret.agent.plist',
        windows_script=output_dir / 'install-egret-service.ps1',
    )
    paths.systemd_unit.write_text(render_systemd_unit(config), encoding='utf-8')
    paths.launchd_plist.write_text(render_launchd_plist(config), encoding='utf-8')
    paths.windows_script.write_text(render_windows_service_script(config), encoding='utf-8')
    return paths
