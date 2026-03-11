# SPDX-License-Identifier: 0BSD
"""Background credential-refresh daemon for aws-xfa.

One daemon instance is started per AWS profile. Each instance manages only
the credentials for its assigned profile.

Dispatches to the appropriate OS primitive:
  macOS   - LaunchAgent plist + launchctl   (one plist per profile)
  Linux   - systemd user unit               (one unit per profile)
  Windows - DETACHED_PROCESS + schtasks     (one task per profile)
"""

import configparser
import datetime
import logging
import logging.handlers
import os
import pathlib
import platform
import signal
import subprocess
import sys
import time

# ── Config dir ───────────────────────────────────────────────────────────────


def _config_dir():
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return pathlib.Path(base) / "aws-xfa"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = pathlib.Path(xdg) if xdg else pathlib.Path.home() / ".config"
    return base / "aws-xfa"


CONFIG_DIR = _config_dir()

REFRESH_BEFORE_SECS = 300  # wake 5 min before expiry
MIN_SLEEP_SECS = 60  # floor for normal sleep
FAILURE_BACKOFF_SECS = 300  # 5-min backoff after refresh failure
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 14

# Output logger — shares the colored stdout handler set up by setup_logger()
_out = logging.getLogger("aws-xfa")

# ── Per-profile path helpers ─────────────────────────────────────────────────


def _pid_file(profile):
    return CONFIG_DIR / ("daemon-%s.pid" % profile)


def _error_log(profile):
    return CONFIG_DIR / ("errors-%s.log" % profile)


def _launchagent_label(profile):
    return "com.user.aws-xfa-daemon-%s" % profile


def _launchagent_plist(profile):
    return (
        pathlib.Path.home()
        / "Library"
        / "LaunchAgents"
        / (_launchagent_label(profile) + ".plist")
    )


def _systemd_dir():
    """Return the systemd user unit directory, respecting XDG_CONFIG_HOME."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = pathlib.Path(xdg) if xdg else pathlib.Path.home() / ".config"
    return base / "systemd" / "user"


def _systemd_service_name(profile):
    return "aws-xfa-daemon-%s" % profile


def _systemd_service_file(profile):
    return _systemd_dir() / (_systemd_service_name(profile) + ".service")


def _schtasks_name(profile):
    return "aws-xfa-daemon-%s" % profile


def _startup_dir():
    """Return the Windows Startup folder for the current user."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    return (
        pathlib.Path(appdata)
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )


def _startup_bat(profile):
    return _startup_dir() / ("aws-xfa-daemon-%s.bat" % profile)


# ── Logging ──────────────────────────────────────────────────────────────────


def setup_error_log(profile):
    """Return a logger that appends errors to the profile's error log."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger("aws-xfa.daemon.%s" % profile)
    if log.handlers:
        return log
    handler = logging.handlers.RotatingFileHandler(
        filename=_error_log(profile),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.ERROR)
    handler.setFormatter(logging.Formatter("%(asctime)s ERROR %(name)s: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.ERROR)
    return log


# ── PID management ───────────────────────────────────────────────────────────


def _write_pid(profile):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _pid_file(profile).write_text(str(os.getpid()))


def _read_pid(profile):
    try:
        return int(_pid_file(profile).read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _pid_alive(pid):
    if platform.system() == "Windows":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # process exists, different uid


def _remove_pid(profile):
    try:
        _pid_file(profile).unlink()
    except FileNotFoundError:
        pass


# ── Credential helpers ───────────────────────────────────────────────────────


def _read_expiration(creds_path, profile):
    """Return credential expiration datetime for *profile*, or None."""
    cfg = configparser.RawConfigParser()
    try:
        cfg.read(creds_path)
        exp_str = cfg.get(profile, "expiration")
        return datetime.datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


# ── Refresh ──────────────────────────────────────────────────────────────────


def refresh_profile(profile, log):
    """Invoke aws-xfa for *profile* as a subprocess. Returns True on success.
    Uses sys.executable to guarantee the correct venv/PATH."""
    try:
        env = os.environ.copy()
        if platform.system() == "Windows":
            # Detached daemon may not inherit PATH additions.
            op_dir = os.path.join(os.path.expanduser("~"), "1PasswordCLI")
            env["PATH"] = op_dir + os.pathsep + env.get("PATH", "")
            env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, "-m", "awsxfa", profile, "--force", "--1pass"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=60,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            log.error(
                "refresh failed for profile '%s' (exit %d): %s",
                profile,
                result.returncode,
                result.stderr.strip(),
            )
            return False
        return True
    except subprocess.TimeoutExpired:
        log.error("refresh timed out for profile '%s'", profile)
        return False
    except Exception as exc:
        log.error("refresh error for profile '%s': %s", profile, exc)
        return False


# ── Main loop ────────────────────────────────────────────────────────────────


def run_refresh_loop(creds_path, profile):
    """Run indefinitely, refreshing credentials for *profile* before expiry."""
    log = setup_error_log(profile)
    _write_pid(profile)

    def _handle_sig(signum, frame):
        _remove_pid(profile)
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle_sig)
        except (OSError, ValueError):
            pass  # SIGTERM not settable on Windows

    while True:
        from awsxfa.xfa_config import load_xfa_config, get_1pass_item

        xfa_config = load_xfa_config()
        if not get_1pass_item(xfa_config, profile):
            log.error("No 1Password item configured for profile '%s'", profile)
            time.sleep(FAILURE_BACKOFF_SECS)
            continue

        now = datetime.datetime.utcnow()
        exp = _read_expiration(creds_path, profile)

        if exp is None:
            ok = refresh_profile(profile, log)
            sleep_for = FAILURE_BACKOFF_SECS if not ok else MIN_SLEEP_SECS
        else:
            remaining = (exp - now).total_seconds()
            if remaining <= REFRESH_BEFORE_SECS:
                ok = refresh_profile(profile, log)
                if not ok:
                    sleep_for = FAILURE_BACKOFF_SECS
                else:
                    new_exp = _read_expiration(creds_path, profile)
                    if new_exp:
                        new_rem = (new_exp - now).total_seconds()
                        sleep_for = max(MIN_SLEEP_SECS, new_rem - REFRESH_BEFORE_SECS)
                    else:
                        sleep_for = MIN_SLEEP_SECS
            else:
                sleep_for = max(MIN_SLEEP_SECS, remaining - REFRESH_BEFORE_SECS)

        time.sleep(sleep_for)


# ── macOS: LaunchAgent ───────────────────────────────────────────────────────


_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{python}</string>
    <string>-m</string>
    <string>awsxfa</string>
    <string>--daemon-loop</string>
    <string>--profile</string>
    <string>{profile}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{path}</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>{error_log}</string>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
</dict>
</plist>
"""

_ALREADY_MANAGED = (
    "Profile '%s' is already managed by the daemon. "
    "To update after 1Password item changes, run: "
    "aws-xfa daemon delete %s && aws-xfa daemon install %s"
)


def install_launchagent(profile):
    plist = _launchagent_plist(profile)
    if plist.exists():
        _out.info(_ALREADY_MANAGED, profile, profile, profile)
        return
    plist.parent.mkdir(parents=True, exist_ok=True)
    plist.write_text(
        _PLIST_TEMPLATE.format(
            label=_launchagent_label(profile),
            python=sys.executable,
            profile=profile,
            error_log=_error_log(profile),
            path=os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        )
    )
    result = subprocess.run(
        ["launchctl", "load", "-w", str(plist)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("launchctl load failed: %s" % result.stderr.strip())
    _out.info("Daemon installed and started for profile '%s'.", profile)
    _out.info("Plist: %s", plist)
    _out.info("Logs:  %s", _error_log(profile))


def remove_launchagent(profile):
    plist = _launchagent_plist(profile)
    if plist.exists():
        subprocess.run(
            ["launchctl", "unload", "-w", str(plist)],
            capture_output=True,
        )
        plist.unlink(missing_ok=True)
        _out.info("Daemon stopped and LaunchAgent removed for profile '%s'.", profile)
    else:
        _out.warning("No LaunchAgent found for profile '%s' at %s", profile, plist)


def status_launchagent(profile):
    plist = _launchagent_plist(profile)
    installed = plist.exists()
    _out.info(
        "LaunchAgent [%s]: %s",
        profile,
        "installed" if installed else "not installed",
    )
    if installed:
        result = subprocess.run(
            ["launchctl", "list", _launchagent_label(profile)],
            capture_output=True,
            text=True,
        )
        state = "running" if result.returncode == 0 else "not running"
        _out.info("launchctl:       %s", state)


# ── Linux: systemd user unit (with double-fork fallback) ─────────────────────


_SERVICE_TEMPLATE = """\
[Unit]
Description=aws-xfa credential refresh daemon ({profile})

[Service]
ExecStart={python} -m awsxfa --daemon-loop --profile {profile}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"""


def _has_systemd():
    """Return True if a systemd user session is reachable."""
    import shutil

    if not shutil.which("systemctl"):
        return False
    try:
        r = subprocess.run(
            ["systemctl", "--user", "is-system-running"],
            capture_output=True,
            timeout=5,
        )
        # 0 = running, 1 = degraded — both confirm systemd is present
        return r.returncode in (0, 1)
    except Exception:
        return False


def install_systemd(profile):
    svc_file = _systemd_service_file(profile)
    if svc_file.exists():
        _out.info(_ALREADY_MANAGED, profile, profile, profile)
        return
    svc_file.parent.mkdir(parents=True, exist_ok=True)
    svc_file.write_text(
        _SERVICE_TEMPLATE.format(
            profile=profile,
            python=sys.executable,
        )
    )
    svc_name = _systemd_service_name(profile)
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        check=True,
    )
    subprocess.run(
        ["systemctl", "--user", "enable", "--now", svc_name],
        check=True,
    )
    _out.info("Daemon installed and started for profile '%s'.", profile)
    _out.info("Service file: %s", svc_file)
    _out.info("Logs:         journalctl --user -u %s -f", svc_name)


def remove_systemd(profile):
    svc_name = _systemd_service_name(profile)
    subprocess.run(
        ["systemctl", "--user", "disable", "--now", svc_name],
        capture_output=True,
    )
    _systemd_service_file(profile).unlink(missing_ok=True)
    subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True,
    )
    _out.info("Daemon stopped and systemd unit removed for profile '%s'.", profile)


def status_systemd(profile):
    subprocess.run(
        ["systemctl", "--user", "status", _systemd_service_name(profile)],
    )


def daemonize():
    """POSIX double-fork to detach from the controlling terminal."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    import resource

    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    for fd in range(3, min(maxfd, 1024)):
        try:
            os.close(fd)
        except OSError:
            pass
    devnull = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    os.close(devnull)


def install_linux(profile, creds_path):
    if _has_systemd():
        install_systemd(profile)
        return
    # Fallback: double-fork (Alpine/OpenRC/WSL without systemd)
    pid = _read_pid(profile)
    if pid and _pid_alive(pid):
        _out.info(_ALREADY_MANAGED, profile, profile, profile)
        return
    _out.warning("No systemd detected — starting via double-fork.")
    _out.warning("Daemon will not survive reboot on this system.")
    _out.warning("For OpenRC (Alpine), add to /etc/local.d/aws-xfa.start:")
    _out.warning("  %s -m awsxfa --daemon-loop --profile %s &", sys.executable, profile)
    daemonize()
    run_refresh_loop(creds_path, profile)


def stop_linux(profile):
    if _systemd_service_file(profile).exists():
        remove_systemd(profile)
        return
    # Fallback: PID-based
    pid = _read_pid(profile)
    if not pid or not _pid_alive(pid):
        _out.info("Daemon is not running for profile '%s'.", profile)
        _remove_pid(profile)
        return
    try:
        os.kill(pid, signal.SIGTERM)
        _out.info("Sent SIGTERM to daemon for profile '%s' (PID %d).", profile, pid)
    except ProcessLookupError:
        _out.warning("Process not found; cleared stale PID file.")
    _remove_pid(profile)


def status_linux(profile):
    if _systemd_service_file(profile).exists():
        status_systemd(profile)
        return
    # Fallback: PID-based
    pid = _read_pid(profile)
    if pid and _pid_alive(pid):
        _out.info("Daemon running for profile '%s' (PID %d).", profile, pid)
    else:
        _out.info("Daemon is not running for profile '%s'.", profile)


# ── Windows: detached process + schtasks ─────────────────────────────────────


def spawn_detached(profile):
    subprocess.Popen(
        [sys.executable, "-m", "awsxfa", "--daemon-loop", "--profile", profile],
        creationflags=(
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        ),
        close_fds=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def install_windows(profile):
    pid = _read_pid(profile)
    if pid and _pid_alive(pid):
        _out.info(_ALREADY_MANAGED, profile, profile, profile)
        return
    spawn_detached(profile)
    # Try schtasks first (needs admin); fall back to Startup folder.
    try:
        subprocess.run(
            [
                "schtasks.exe",
                "/create",
                "/sc",
                "onlogon",
                "/tn",
                _schtasks_name(profile),
                "/tr",
                (
                    '"%s" -m awsxfa --daemon-loop --profile %s'
                    % (sys.executable, profile)
                ),
                "/f",
            ],
            check=True,
            capture_output=True,
        )
        _out.info("Daemon started and scheduled at logon for profile '%s'.", profile)
    except subprocess.CalledProcessError:
        # schtasks /sc onlogon requires admin — use Startup folder instead.
        bat = _startup_bat(profile)
        bat.parent.mkdir(parents=True, exist_ok=True)
        cmd = '"%s" -m awsxfa --daemon-loop --profile %s' % (
            sys.executable,
            profile,
        )
        bat.write_text('@echo off\nstart "" /b %s\n' % cmd)
        _out.info(
            "Daemon started; scheduled via Startup folder for profile '%s'.",
            profile,
        )
        _out.info("Startup script: %s", bat)


def stop_windows(profile):
    pid = _read_pid(profile)
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    _remove_pid(profile)
    # Remove schtasks entry (if it exists).
    try:
        subprocess.run(
            ["schtasks.exe", "/delete", "/tn", _schtasks_name(profile), "/f"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        pass
    # Remove Startup bat (if it exists).
    bat = _startup_bat(profile)
    bat.unlink(missing_ok=True)
    _out.info(
        "Daemon stopped and startup entries removed for profile '%s'.",
        profile,
    )


def status_windows(profile):
    pid = _read_pid(profile)
    if pid and _pid_alive(pid):
        _out.info("Daemon running for profile '%s' (PID %d).", profile, pid)
    else:
        _out.info("Daemon is not running for profile '%s'.", profile)


# ── Public dispatch ──────────────────────────────────────────────────────────


def daemon_install(profile, creds_path):
    system = platform.system()
    if system == "Darwin":
        install_launchagent(profile)
    elif system == "Linux":
        install_linux(profile, creds_path)
    elif system == "Windows":
        install_windows(profile)
    else:
        _out.warning("Unsupported platform: %s", system)
        sys.exit(1)


def daemon_stop(profile):
    system = platform.system()
    if system == "Darwin":
        remove_launchagent(profile)
    elif system == "Linux":
        stop_linux(profile)
    elif system == "Windows":
        stop_windows(profile)
    else:
        _out.warning("Unsupported platform: %s", system)
        sys.exit(1)


def daemon_delete(profile):
    """Stop daemon, remove OS artifacts and log files for *profile*."""
    daemon_stop(profile)
    _remove_pid(profile)
    err_log = _error_log(profile)
    for f in [err_log] + list(CONFIG_DIR.glob("errors-%s.log.*" % profile)):
        try:
            pathlib.Path(f).unlink()
            _out.info("Removed: %s", f)
        except FileNotFoundError:
            pass
    _out.info("Daemon fully removed for profile '%s'.", profile)


def daemon_status(profile):
    system = platform.system()
    if system == "Darwin":
        status_launchagent(profile)
    elif system == "Linux":
        status_linux(profile)
    elif system == "Windows":
        status_windows(profile)
    else:
        _out.warning("Unsupported platform: %s", system)
        sys.exit(1)
