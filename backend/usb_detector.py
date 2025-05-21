import asyncio
import websockets
import psutil
import json
import platform

HOST = "localhost"
PORT = 12345
CHECK_INTERVAL = 2
connected_clients = set()
known_usb_drives = set()
KNOWN_WEBAUTHN_VIDS_PIDS = []


def get_removable_drives():
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
    if connected_clients:
        print(f"Python: Attempting to send to {len(connected_clients)} client(s): {message}")
        # Use a list comprehension for awaiting multiple sends
        await asyncio.gather(*[client.send(json.dumps(message)) for client in connected_clients])
    else:
        print(f"Python: No clients connected. Message not sent: {message}")


async def usb_monitor():
    global known_usb_drives
    print("Python usb_monitor: Started.")
    known_usb_drives = get_removable_drives()
    print(f"Python usb_monitor: Initial removable drives (normal USBs): {known_usb_drives}")
    while True:
        await asyncio.sleep(CHECK_INTERVAL)
        current_drives = get_removable_drives()
        newly_connected = current_drives - known_usb_drives
        newly_disconnected = known_usb_drives - current_drives
        if newly_connected:
            for drive in newly_connected:
                print(f"Python usb_monitor: Normal USB Connected: {drive}")
                await send_to_all({"event": "NORMAL_USB_CONNECTED", "drive": drive})
        if newly_disconnected:
            for drive in newly_disconnected:
                print(f"Python usb_monitor: Normal USB Disconnected: {drive}")
                await send_to_all({"event": "NORMAL_USB_DISCONNECTED", "drive": drive})
        known_usb_drives = current_drives


async def handler(websocket):  # Single argument for websockets v15+
    remote_addr_info = websocket.remote_address
    client_id_str = "unknown_client"
    if isinstance(remote_addr_info, tuple) and len(remote_addr_info) >= 2:
        client_id_str = f"{remote_addr_info[0]}:{remote_addr_info[1]}"  # Use first two elements
    elif isinstance(remote_addr_info, (str, bytes)):
        client_id_str = str(remote_addr_info)

    print(f"Python Handler: Client {client_id_str} connected. Adding to connected_clients.")
    connected_clients.add(websocket)
    print(f"Python Handler: connected_clients now has {len(connected_clients)} client(s).")
    try:
        print(f"Python Handler: Sending initial state to client {client_id_str}.")
        if known_usb_drives:
            await websocket.send(json.dumps(
                {"event": "NORMAL_USB_CONNECTED", "drive": list(known_usb_drives)[0], "initial_state": True}))
        else:
            await websocket.send(json.dumps({"event": "NORMAL_USB_DISCONNECTED", "initial_state": True}))
        print(f"Python Handler: Initial state sent to client {client_id_str}.")
        async for message in websocket:
            print(f"Python Handler: Client {client_id_str} sent message: {message}")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"Python Handler: Client {client_id_str} connection closed normally. Code: {e.code}, Reason: {e.reason}")
    except websockets.exceptions.ConnectionClosedOK as e:
        print(f"Python Handler: Client {client_id_str} connection closed OK. Code: {e.code}, Reason: {e.reason}")
    except Exception as e:
        print(f"Python Handler: Error with client {client_id_str}: {type(e).__name__} - {e}")
    finally:
        print(f"Python Handler: Client {client_id_str} finalizing. Removing from connected_clients.")
        connected_clients.discard(websocket)
        print(
            f"Python Handler: connected_clients now has {len(connected_clients)} client(s) after removal of {client_id_str}.")


async def main():
    print("Python main: Starting USB monitor task...")
    monitor_task = asyncio.create_task(usb_monitor())
    print("Python main: Starting WebSocket server...")
    server = await websockets.serve(handler, HOST, PORT)
    print(f"Python main: WebSocket server started on ws://{HOST}:{PORT}")
    await server.wait_closed()
    print("Python main: Server wait_closed completed. Cancelling monitor task.")
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        print("Python main: Monitor task successfully cancelled.")


if __name__ == "__main__":
    print("Python script: Starting.")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Python script: Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        print(f"Python script: An unexpected error occurred in __main__: {type(e).__name__} - {e}")
    finally:
        print("Python script: Exiting.")