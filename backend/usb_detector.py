import asyncio
import websockets
import psutil
import json
import platform

# --- Configuration ---
HOST = "localhost"
PORT = 12345  # Port for the WebSocket server
CHECK_INTERVAL = 2  # Seconds

# --- State ---
connected_clients = set()
# Using disk partitions as a proxy for USB storage devices.
# We store mountpoints of removable drives.
known_usb_drives = set()

# --- WebAuthn Key Identification (Placeholder) ---
# In a more advanced version, we'd populate this with VIDs/PIDs
# or other identifiers of known WebAuthn security keys to ignore them.
# For now, we assume any detected removable drive is "normal".
KNOWN_WEBAUTHN_VIDS_PIDS = [
    # Example: ("0x1050", "0x0407") # Yubico YubiKey 5
]


def get_removable_drives():
    """
    Identifies removable USB storage devices.
    This is a basic implementation. More sophisticated detection might be needed
    to differentiate various USB device types (e.g., using pyusb).
    """
    drives = set()
    try:
        partitions = psutil.disk_partitions(all=True)
        for p in partitions:
            if 'removable' in p.opts.lower() or 'external' in p.opts.lower():
                if platform.system() == "Windows":
                    if 'cdrom' not in p.opts.lower() and p.fstype != '':
                        drives.add(p.mountpoint)
                elif platform.system() == "Linux":
                    if p.mountpoint.startswith(('/media', '/mnt')) and p.fstype != '':
                        drives.add(p.mountpoint)
                elif platform.system() == "Darwin":
                    if p.mountpoint.startswith(
                            '/Volumes/') and p.fstype != '' and p.mountpoint != '/Volumes/Macintosh HD':
                        drives.add(p.mountpoint)
    except Exception as e:
        print(f"Error getting disk partitions: {e}")
    return drives


async def send_to_all(message):
    """Sends a message to all connected WebSocket clients."""
    if connected_clients:
        await asyncio.wait([client.send(json.dumps(message)) for client in connected_clients])


async def usb_monitor():
    """Monitors USB drive changes and notifies clients."""
    global known_usb_drives
    print("USB monitor started.")

    known_usb_drives = get_removable_drives()
    print(f"Initial removable drives (normal USBs): {known_usb_drives}")

    while True:
        await asyncio.sleep(CHECK_INTERVAL)
        current_drives = get_removable_drives()

        newly_connected = current_drives - known_usb_drives
        newly_disconnected = known_usb_drives - current_drives

        if newly_connected:
            for drive in newly_connected:
                print(f"Normal USB Connected: {drive}")
                await send_to_all({"event": "NORMAL_USB_CONNECTED", "drive": drive})

        if newly_disconnected:
            for drive in newly_disconnected:
                print(f"Normal USB Disconnected: {drive}")
                await send_to_all({"event": "NORMAL_USB_DISCONNECTED", "drive": drive})

        known_usb_drives = current_drives


async def handler(websocket, path):
    """Handles new WebSocket connections."""
    print(f"Client connected from {path}")
    connected_clients.add(websocket)
    try:
        # Send current state upon connection
        if known_usb_drives:
            await websocket.send(json.dumps(
                {"event": "NORMAL_USB_CONNECTED", "drive": list(known_usb_drives)[0], "initial_state": True}))
        else:
            await websocket.send(json.dumps({"event": "NORMAL_USB_DISCONNECTED", "initial_state": True}))

        async for message in websocket:
            print(f"Received message: {message}")
    except websockets.exceptions.ConnectionClosedError:
        print("Client connection closed.")
    except Exception as e:
        print(f"Error in handler: {e}")
    finally:
        connected_clients.remove(websocket)
        print("Client disconnected.")


async def main():
    monitor_task = asyncio.create_task(usb_monitor())
    server = await websockets.serve(handler, HOST, PORT)
    print(f"WebSocket server started on ws://{HOST}:{PORT}")

    await server.wait_closed()
    monitor_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down...")
