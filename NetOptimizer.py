# -*- coding: utf-8 -*-
"""
NetOptimizer Pro (Safe Edition)
Relatively low-risk tuning for reducing latency on Windows.

What it does:
- Runs only on Windows and only with Administrator privileges.
- Creates a backup (netoptimizer_backup.json) of registry and services it touches.
- Can restore all changes from backup.
- Disables Nagle's Algorithm on active network interfaces (with IPs).
- Minimizes Windows Telemetry and disables a few non-essential, relatively safe services.

Note:
This script cannot fix issues caused by your ISP, bad modem/router, weak Wi-Fi,
congested network, or global internet routing. It only optimizes local system settings.
"""

import os
import sys
import json
import ctypes
import subprocess
from typing import Dict, Any, Optional

try:
    import winreg
except ImportError:
    winreg = None  # We should never reach here on non-Windows platforms


BACKUP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netoptimizer_backup.json")


# ===============================
# Generic helpers
# ===============================

def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(cmd: str) -> int:
    """Run a shell command and return the returncode, without crashing the program."""
    try:
        completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return completed.returncode
    except Exception:
        return -1


def load_backup() -> Dict[str, Any]:
    if not os.path.exists(BACKUP_FILE):
        return {}
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def save_backup(data: Dict[str, Any]) -> None:
    try:
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("⚠️ Error saving backup file:", e)


# ===============================
# Registry helpers
# ===============================

def reg_get_value(root, path: str, name: str) -> Optional[Any]:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None
    except OSError:
        return None


def reg_set_dword(root, path: str, name: str, value: int) -> None:
    try:
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
    except Exception as e:
        print(f"⚠️ Error setting registry {path}\\{name}:", e)


def reg_delete_value(root, path: str, name: str) -> None:
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_WRITE) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass
    except OSError:
        # Probably didn't exist or we lacked permissions – not fatal
        pass


# ===============================
# Service management
# ===============================

SAFE_SERVICES = {
    # Relatively low-risk services to disable for gaming/latency purposes
    "DiagTrack": "Connected User Experiences and Telemetry (DiagTrack)",
    "dmwappushservice": "WAP Push Message Routing",
    "RemoteRegistry": "Remote Registry",
}


def get_service_start_type(service_name: str) -> Optional[int]:
    """
    Read the Start value from the service registry key.
    2 = Automatic, 3 = Manual, 4 = Disabled
    """
    try:
        path = fr"SYSTEM\CurrentControlSet\Services\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "Start")
            return int(value)
    except Exception:
        return None


def set_service_start_type(service_name: str, start_type: int) -> bool:
    """
    Set the Start value in registry and use sc config for extra assurance.
    """
    ok = True
    try:
        path = fr"SYSTEM\CurrentControlSet\Services\{service_name}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(start_type))
    except Exception:
        ok = False

    # Attempt to set using sc config (may not always succeed)
    if start_type == 2:
        start_str = "auto"
    elif start_type == 3:
        start_str = "demand"
    elif start_type == 4:
        start_str = "disabled"
    else:
        start_str = None

    if start_str:
        rc = run_cmd(f'sc config "{service_name}" start= {start_str}')
        if rc != 0:
            ok = False

    return ok


def stop_service(service_name: str) -> None:
    run_cmd(f'sc stop "{service_name}"')


# ===============================
# Nagle’s Algorithm
# ===============================

def optimize_nagle(backup: Dict[str, Any]) -> None:
    """
    Disable Nagle's Algorithm on interfaces that have an IP.
    """
    print("\n🔧 Optimizing Nagle's Algorithm on network interfaces...")

    interfaces_root = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_root, 0, winreg.KEY_READ | winreg.KEY_WRITE) as root_key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root_key, i)
                except OSError:
                    break
                i += 1

                sub_path = interfaces_root + "\\" + subkey_name
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as iface_key:
                        ip = None
                        try:
                            ip, _ = winreg.QueryValueEx(iface_key, "DhcpIPAddress")
                            if not ip:
                                raise ValueError
                        except Exception:
                            try:
                                ip, _ = winreg.QueryValueEx(iface_key, "IPAddress")
                                if isinstance(ip, list):
                                    ip = ip[0] if ip else None
                            except Exception:
                                ip = None

                        if not ip or ip in ("0.0.0.0", "127.0.0.1"):
                            continue  # Not an active interface

                        # Existing backup entry for this interface
                        nagle_backup = backup.setdefault("nagle", {})
                        iface_backup = nagle_backup.setdefault(subkey_name, {})

                        # Save previous values (or "NO_EXIST" marker)
                        old_ack = reg_get_value(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpAckFrequency")
                        old_nodelay = reg_get_value(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpNoDelay")
                        iface_backup.setdefault("TcpAckFrequency", old_ack if old_ack is not None else "NO_EXIST")
                        iface_backup.setdefault("TcpNoDelay", old_nodelay if old_nodelay is not None else "NO_EXIST")

                        # Apply new values
                        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpAckFrequency", 1)
                        reg_set_dword(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpNoDelay", 1)
                        print(f"✅ Nagle disabled on interface {subkey_name} (IP: {ip})")

                except PermissionError:
                    print(f"⚠️ Not enough permissions for interface {subkey_name}.")
                except Exception as e:
                    print(f"⚠️ Error on interface {subkey_name}: {e}")

    except Exception as e:
        print("⚠️ Error accessing interface registry keys:", e)


def restore_nagle(backup: Dict[str, Any]) -> None:
    nagle_backup = backup.get("nagle") or {}
    if not nagle_backup:
        return

    interfaces_root = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    print("\n♻️ Restoring Nagle-related settings...")

    for subkey_name, iface_backup in nagle_backup.items():
        sub_path = interfaces_root + "\\" + subkey_name
        old_ack = iface_backup.get("TcpAckFrequency", "NO_EXIST")
        old_nodelay = iface_backup.get("TcpNoDelay", "NO_EXIST")

        if old_ack == "NO_EXIST":
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpAckFrequency")
        else:
            reg_set_dword(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpAckFrequency", int(old_ack))

        if old_nodelay == "NO_EXIST":
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpNoDelay")
        else:
            reg_set_dword(winreg.HKEY_LOCAL_MACHINE, sub_path, "TcpNoDelay", int(old_nodelay))

        print(f"✅ Restored Nagle settings for interface {subkey_name}.")


# ===============================
# Telemetry and safe services
# ===============================

def optimize_telemetry_and_services(backup: Dict[str, Any]) -> None:
    print("\n🔧 Disabling Telemetry and a few non-essential services...")

    # Backup and set AllowTelemetry
    data_coll_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    old_telemetry = reg_get_value(winreg.HKEY_LOCAL_MACHINE, data_coll_path, "AllowTelemetry")
    backup.setdefault("telemetry", {})
    if "AllowTelemetry" not in backup["telemetry"]:
        backup["telemetry"]["AllowTelemetry"] = old_telemetry if old_telemetry is not None else "NO_EXIST"

    reg_set_dword(winreg.HKEY_LOCAL_MACHINE, data_coll_path, "AllowTelemetry", 0)
    print("✅ AllowTelemetry set to 0 (Telemetry disabled or minimized).")

    # Services
    svc_backup = backup.setdefault("services", {})
    for svc, desc in SAFE_SERVICES.items():
        if svc not in svc_backup:
            svc_backup[svc] = {}

        original_start = get_service_start_type(svc)
        if "Start" not in svc_backup[svc]:
            svc_backup[svc]["Start"] = original_start if original_start is not None else "NO_EXIST"

        # Disable these services; in normal consumer usage they are not critical
        if set_service_start_type(svc, 4):
            print(f"✅ Service {svc} ({desc}) disabled.")
            stop_service(svc)
        else:
            print(f"⚠️ Could not fully configure service {svc} (might be permission or Windows version limitations).")


def restore_telemetry_and_services(backup: Dict[str, Any]) -> None:
    print("\n♻️ Restoring Telemetry and services...")

    # Telemetry
    data_coll_path = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    telemetry_backup = backup.get("telemetry") or {}
    if "AllowTelemetry" in telemetry_backup:
        old = telemetry_backup["AllowTelemetry"]
        if old == "NO_EXIST":
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, data_coll_path, "AllowTelemetry")
        else:
            reg_set_dword(winreg.HKEY_LOCAL_MACHINE, data_coll_path, "AllowTelemetry", int(old))
        print("✅ AllowTelemetry restored.")

    # Services
    svc_backup = backup.get("services") or {}
    for svc, info in svc_backup.items():
        old_start = info.get("Start", "NO_EXIST")
        if old_start == "NO_EXIST":
            continue
        if set_service_start_type(svc, int(old_start)):
            print(f"✅ Service {svc} StartType restored to previous value ({old_start}).")
        else:
            print(f"⚠️ Could not restore StartType for service {svc}.")


# ===============================
# Main logic
# ===============================

def apply_optimizations():
    backup = load_backup()

    if backup.get("applied"):
        print("ℹ️ It looks like optimizations have already been applied. If you want to revert, choose Restore.")
    else:
        print("📦 Creating backup of current settings (registry and related services)...")

    # Apply optimizations
    optimize_nagle(backup)
    optimize_telemetry_and_services(backup)

    backup["applied"] = True
    save_backup(backup)

    print("\n✅ Optimizations applied.")
    print("📌 Recommendation: restart your system once so all settings fully take effect.")
    print("⚠️ If you see strange behavior later, run this script again and choose Restore.")


def restore_all():
    backup = load_backup()
    if not backup:
        print("ℹ️ No valid backup found. Nothing to restore.")
        return

    restore_nagle(backup)
    restore_telemetry_and_services(backup)

    backup["applied"] = False
    save_backup(backup)

    print("\n✅ Settings restored as far as possible.")
    print("📌 Recommendation: restart your system.")


def main():
    if not is_windows():
        print("❌ This script can only be run on Windows.")
        sys.exit(1)

    if winreg is None:
        print("❌ winreg is not available. Use Windows Python runtime to run this script.")
        sys.exit(1)

    if not is_admin():
        print("⚠️ Please run this script as Administrator (Run as Administrator).")
        input("Press any key to exit...")
        sys.exit(1)

    print("🚀 NetOptimizer Pro (Safe Edition)")
    print("This tool applies relatively low-risk settings to reduce latency.")
    print("There is no guarantee of dramatic ping or packet-loss improvements,")
    print("but it tunes your system in a reasonable way for gaming and low latency.\n")

    backup_exists = bool(load_backup())

    while True:
        print("Menu:")
        print("  1) Apply optimizations")
        print("  2) Restore from backup")
        print("  3) Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            apply_optimizations()
            break
        elif choice == "2":
            if not backup_exists:
                print("ℹ️ No backup exists yet; you must first run option 1 at least once.")
            else:
                restore_all()
                break
        elif choice == "3":
            print("Exiting.")
            break
        else:
            print("❌ Invalid option. Please try again.\n")


if __name__ == "__main__":
    main()
