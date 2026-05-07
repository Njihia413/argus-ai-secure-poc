"""
Machine Fingerprint Utility Module for Argus AI

Generates a deterministic, composite hardware fingerprint for machine binding.
The fingerprint is a SHA-256 hash derived from multiple platform-specific
identifiers (hostname, OS, machine UUID, primary NIC MAC address).

References:
  - NIST SP 800-207 (Zero Trust Architecture) — device trust verification
  - FIDO Alliance Enterprise Attestation — binding credentials to devices
  - Yubico Developer Docs — PIV attestation and device binding strategies
"""

import hashlib
import platform
import subprocess
import uuid

# Bump this whenever the hash inputs change. The frontend reads it from the
# cached components dict and treats a mismatch as a cache miss, so users don't
# silently bind/login with hashes computed under a previous algorithm.
FINGERPRINT_VERSION = "v2"


def generate_machine_fingerprint():
    """
    Generate a deterministic machine fingerprint.

    The hash is derived ONLY from the OS family + the platform's hardware/install
    UUID — components that don't drift on OS patches, network changes, or virtual
    interface churn. The earlier algorithm hashed `platform.release()` (which
    shifts on every OS minor update) and `uuid.getnode()` (which is documented
    to return *any* available MAC on multi-NIC machines), and bindings would
    silently break for users whenever those changed.

    The returned `components` dict is intentionally richer than the hash inputs:
    it carries hostname, OS release, and MAC address for the admin UI to display,
    but those values do NOT participate in the hash.

    Returns:
        tuple: (machine_id: str, components: dict)
            - machine_id: SHA-256 hex digest of the stable subset
            - components: dict of identifier values (informational + hashed)
    """
    machine_uuid = _get_machine_uuid()
    os_family = platform.system()

    # Stable subset — these are what the hash is computed from. Adding
    # anything else here will reintroduce churn.
    hashed = {
        "machine_uuid": machine_uuid,
        "os_family": os_family,
    }
    fingerprint_string = "|".join(
        sorted(f"{k}={v}" for k, v in hashed.items())
    )
    machine_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()

    # Full informational set for the admin UI. Anything beyond `hashed` is
    # display-only and safe to evolve without invalidating bindings.
    components = {
        **hashed,
        "fingerprint_version": FINGERPRINT_VERSION,
        "hostname": _get_stable_hostname(),
        "os": f"{os_family}-{platform.release()}",
        "mac_address": _get_primary_mac(),
    }

    return machine_id, components


def _get_stable_hostname():
    """
    Get a stable hostname that doesn't change with network.

    - macOS: scutil --get ComputerName (set in System Settings),
             falls back to scutil --get LocalHostName
    - Linux/Windows: platform.node() (typically stable on these platforms)
    """
    system = platform.system()

    if system == "Darwin":
        for key in ("ComputerName", "LocalHostName"):
            try:
                result = subprocess.run(
                    ["scutil", "--get", key],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                name = result.stdout.strip()
                if name:
                    return name
            except Exception:
                continue

    return platform.node()


def _get_machine_uuid():
    """
    Get platform-specific machine UUID.

    - macOS: IOPlatformUUID from IORegistry
    - Linux: /etc/machine-id or /sys/class/dmi/id/product_uuid
    - Windows: WMIC csproduct UUID
    """
    system = platform.system()

    try:
        if system == "Darwin":  # macOS
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "IOPlatformUUID" in line:
                    # Extract UUID from line like: "IOPlatformUUID" = "XXXXXXXX-..."
                    return line.split('"')[-2]

        elif system == "Linux":
            # Try /etc/machine-id first (most common on modern Linux)
            try:
                with open("/etc/machine-id") as f:
                    return f.read().strip()
            except FileNotFoundError:
                pass
            # Fallback to DMI product UUID (requires root on some distros)
            try:
                with open("/sys/class/dmi/id/product_uuid") as f:
                    return f.read().strip()
            except (FileNotFoundError, PermissionError):
                pass

        elif system == "Windows":
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            lines = [
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip() and line.strip() != "UUID"
            ]
            if lines:
                return lines[0]

    except Exception as e:
        print(f"Warning: Could not determine machine UUID: {e}")

    # Last-resort fallback: use uuid.getnode() which derives from MAC
    return f"fallback-{uuid.getnode()}"


def _get_primary_mac():
    """
    Get the primary network interface MAC address as a hex string.
    Uses uuid.getnode() which returns the hardware address as a 48-bit integer.
    """
    mac_int = uuid.getnode()
    # Format as colon-separated hex (e.g., "aa:bb:cc:dd:ee:ff")
    mac_hex = ":".join(
        f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6))
    )
    return mac_hex


def validate_fingerprint(stored_machine_id, current_components=None):
    """
    Validate that the current machine matches a stored fingerprint.

    Args:
        stored_machine_id: The SHA-256 hash stored in the database
        current_components: Optional pre-computed components dict.
                           If None, regenerates from current machine.

    Returns:
        bool: True if fingerprints match
    """
    if current_components:
        # Hash only the stable subset — must match generate_machine_fingerprint().
        hashed = {
            "machine_uuid": current_components.get("machine_uuid"),
            "os_family": current_components.get("os_family") or platform.system(),
        }
        fingerprint_string = "|".join(
            sorted(f"{k}={v}" for k, v in hashed.items())
        )
        current_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    else:
        current_id, _ = generate_machine_fingerprint()

    return current_id == stored_machine_id


def enumerate_installed_apps(detect_hints_by_slug):
    """
    Detect which of the requested applications are installed on this host.

    Args:
        detect_hints_by_slug: dict of {slug: detect_hints_dict}. detect_hints
            understood keys:
              - windows_registry: exe name under HKLM Uninstall / App Paths
              - macos_bundle_id:  bundle id to resolve via mdfind/LaunchServices
              - linux_desktop:    .desktop filename under /usr/share/applications

    Returns:
        list of dicts: [{"slug": str, "version": str | None}, ...] — only slugs
        that were detected are returned.
    """
    system = platform.system()
    detected = []

    for slug, hints in (detect_hints_by_slug or {}).items():
        hints = hints or {}
        found, version = False, None

        try:
            if system == "Darwin":
                bundle_id = hints.get("macos_bundle_id")
                if bundle_id:
                    result = subprocess.run(
                        ["mdfind", f"kMDItemCFBundleIdentifier == '{bundle_id}'"],
                        capture_output=True,
                        text=True,
                        timeout=8,
                    )
                    if result.stdout.strip():
                        found = True

            elif system == "Windows":
                exe_name = hints.get("windows_registry")
                if exe_name:
                    # Look under App Paths — populated by Office et al.
                    try:
                        import winreg  # only available on Windows
                        for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                            try:
                                path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
                                with winreg.OpenKey(root, path):
                                    found = True
                                    break
                            except OSError:
                                continue
                    except ImportError:
                        pass

            elif system == "Linux":
                desktop = hints.get("linux_desktop")
                if desktop:
                    import os
                    for base in ("/usr/share/applications", "/usr/local/share/applications"):
                        if os.path.exists(os.path.join(base, desktop)):
                            found = True
                            break
        except Exception as e:
            print(f"Warning: install-check failed for {slug}: {e}")

        if found:
            detected.append({"slug": slug, "version": version})

    return detected


def enumerate_raw_inventory():
    """Return every installable application the OS knows about.

    Unlike enumerate_installed_apps (which probes for specific catalog entries),
    this scans broadly and returns everything. Admins use this as the
    'promote to catalog' source.

    Returns:
        list of dicts: [{"bundle_id": str|None, "name": str, "path": str|None}, ...]
    """
    system = platform.system()
    inventory = []

    try:
        if system == "Darwin":
            import os
            roots = ["/Applications", os.path.expanduser("~/Applications")]
            for root in roots:
                if not os.path.isdir(root):
                    continue
                for entry in os.listdir(root):
                    if not entry.endswith(".app"):
                        continue
                    app_path = os.path.join(root, entry)
                    name = entry[:-4]
                    bundle_id = None
                    info_plist = os.path.join(app_path, "Contents", "Info.plist")
                    if os.path.isfile(info_plist):
                        try:
                            result = subprocess.run(
                                ["defaults", "read", info_plist, "CFBundleIdentifier"],
                                capture_output=True,
                                text=True,
                                timeout=3,
                            )
                            bundle_id = result.stdout.strip() or None
                        except Exception:
                            pass
                    inventory.append({"bundle_id": bundle_id, "name": name, "path": app_path})

        elif system == "Windows":
            try:
                import winreg
                uninstall_roots = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                ]
                seen_names = set()
                for root, path in uninstall_roots:
                    try:
                        with winreg.OpenKey(root, path) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                subkey_name = winreg.EnumKey(key, i)
                                try:
                                    with winreg.OpenKey(key, subkey_name) as subkey:
                                        try:
                                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                        except FileNotFoundError:
                                            continue
                                        if not name or name in seen_names:
                                            continue
                                        seen_names.add(name)
                                        install_loc = None
                                        try:
                                            install_loc = winreg.QueryValueEx(subkey, "InstallLocation")[0] or None
                                        except FileNotFoundError:
                                            pass
                                        inventory.append({"bundle_id": subkey_name, "name": name, "path": install_loc})
                                except OSError:
                                    continue
                    except OSError:
                        continue
            except ImportError:
                pass

        elif system == "Linux":
            import os
            bases = ["/usr/share/applications", "/usr/local/share/applications",
                     os.path.expanduser("~/.local/share/applications")]
            for base in bases:
                if not os.path.isdir(base):
                    continue
                for fname in os.listdir(base):
                    if not fname.endswith(".desktop"):
                        continue
                    name = fname[:-8]
                    path = os.path.join(base, fname)
                    try:
                        with open(path) as f:
                            for line in f:
                                if line.startswith("Name="):
                                    name = line.split("=", 1)[1].strip()
                                    break
                    except Exception:
                        pass
                    inventory.append({"bundle_id": fname, "name": name, "path": path})

    except Exception as e:
        print(f"Warning: raw inventory scan failed: {e}")

    inventory.sort(key=lambda x: (x.get("name") or "").lower())
    return inventory


if __name__ == "__main__":
    # Quick self-test
    machine_id, components = generate_machine_fingerprint()
    print("Machine Fingerprint Components:")
    for key, value in sorted(components.items()):
        print(f"  {key}: {value}")
    print(f"\nMachine ID (SHA-256): {machine_id}")

    # Verify determinism
    machine_id_2, _ = generate_machine_fingerprint()
    assert machine_id == machine_id_2, "FAIL: Fingerprint is not deterministic!"
    print("\n✓ Determinism check passed")
