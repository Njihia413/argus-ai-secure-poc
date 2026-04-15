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


def generate_machine_fingerprint():
    """
    Generate a deterministic machine fingerprint from hardware/software identifiers.

    Returns:
        tuple: (machine_id: str, components: dict)
            - machine_id: SHA-256 hex digest of the composite fingerprint
            - components: dict of raw identifier values used in generation
    """
    components = {
        "hostname": _get_stable_hostname(),
        "os": f"{platform.system()}-{platform.release()}",
        "machine_uuid": _get_machine_uuid(),
        "mac_address": _get_primary_mac(),
    }

    # Create deterministic hash from sorted key=value pairs
    fingerprint_string = "|".join(
        sorted(f"{k}={v}" for k, v in components.items())
    )
    machine_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()

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
        fingerprint_string = "|".join(
            sorted(f"{k}={v}" for k, v in current_components.items())
        )
        current_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    else:
        current_id, _ = generate_machine_fingerprint()

    return current_id == stored_machine_id


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
