import asyncio
import websockets
import psutil
import json
import platform
import hid # Added for HID device detection
import requests # Added for making HTTP requests to Flask backend

HOST = "localhost"
PORT = 12345
CHECK_INTERVAL = 2 # For normal USB drives
HID_CHECK_INTERVAL = 1 # For HID security keys (can be more frequent)
FLASK_API_URL = "http://localhost:5000/api/verify_key_ownership" # URL for the new verification endpoint

# Dictionary to store client connections and their associated auth tokens
# {websocket_client: "user_auth_token"}
connected_clients = {}
known_usb_drives = set()
known_hid_security_keys = {} # Store as dict: path -> {vendor_id, product_id, serial_number}

# Helper function to identify FIDO devices
def is_fido_device(device_info):
    # Standard FIDO HID check
    if device_info.get('usage_page') == 0xF1D0 and device_info.get('usage') == 0x01:
        return True

    # Fallback checks for common FIDO keys like YubiKey based on VID/PID and product string
    yubico_vid = 0x1050 
    yubikey_fido_pids = [
        0x0018, 0x0110, 0x0111, 0x0114, 0x0115, 0x0116, 0x0120, 0x0200,
        0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407, 0x0410,
    ]

    vid = device_info.get('vendor_id')
    pid = device_info.get('product_id')
    product_string = device_info.get('product_string', "").lower()

    if vid == yubico_vid and pid in yubikey_fido_pids:
        # print(f"    -> Matched YubiKey by VID/PID: {vid:04x}/{pid:04x}") # Commented out to prevent repeated messages
        return True
    
    if "fido" in product_string:
        print(f"    -> Matched by 'fido' in product string: {product_string}")
        return True
        
    return False

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
        # print(f"Python: Attempting to send to {len(connected_clients)} client(s): {message}") # Can be noisy
        await asyncio.gather(*[client.send(json.dumps(message)) for client in connected_clients.keys()])
    # else:
        # print(f"Python: No clients connected. Message not sent: {message}") # Can be noisy

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

async def hid_security_key_monitor():
    global known_hid_security_keys
    print("Python hid_security_key_monitor: Started. Continuously monitoring for FIDO security keys...")
    
    # Initial scan to populate known_hid_security_keys
    current_hid_devices_initial_scan = {}
    try:
        for dev_info in hid.enumerate():
            if is_fido_device(dev_info):
                path = dev_info['path'].decode('utf-8') if isinstance(dev_info['path'], bytes) else dev_info['path']
                current_hid_devices_initial_scan[path] = {
                    'vendor_id': dev_info['vendor_id'],
                    'product_id': dev_info['product_id'],
                    'product_string': dev_info.get('product_string', 'N/A'),
                    'serial_number': dev_info.get('serial_number', 'N/A')
                }
    except Exception as e:
        print(f"Python hid_security_key_monitor: Error during initial HID scan: {e}")
    known_hid_security_keys = current_hid_devices_initial_scan
    if known_hid_security_keys:
        print(f"Python hid_security_key_monitor: Initial known FIDO devices: {list(known_hid_security_keys.keys())}")

    # Continuous monitoring loop
    while True: 
        await asyncio.sleep(HID_CHECK_INTERVAL)
        
        current_active_fido_devices_in_this_scan = {} # FIDO devices found in the current scan iteration
        
        try:
            # Enumerate all HID devices
            for dev_info_loop in hid.enumerate():
                # Check if it's a FIDO device based on our criteria
                if is_fido_device(dev_info_loop):
                    path = dev_info_loop['path'].decode('utf-8') if isinstance(dev_info_loop['path'], bytes) else dev_info_loop['path']
                    current_active_fido_devices_in_this_scan[path] = {
                        'vendor_id': dev_info_loop['vendor_id'],
                        'product_id': dev_info_loop['product_id'],
                        'product_string': dev_info_loop.get('product_string', 'N/A'),
                        'serial_number': dev_info_loop.get('serial_number', 'N/A')
                    }
        except Exception as e:
            print(f"Python hid_security_key_monitor: Error during HID enumeration loop: {e}")
            await asyncio.sleep(HID_CHECK_INTERVAL * 2) # Longer sleep on error before retrying
            continue # Skip to the next iteration

        new_connections_found_this_cycle = False
        # --- Detect newly connected FIDO devices ---
        for path, info in current_active_fido_devices_in_this_scan.items():
            if path not in known_hid_security_keys: # Device is in current scan but not in our known list
                new_connections_found_this_cycle = True
                print(f"Python hid_security_key_monitor: New FIDO Security Key Connected: VID={info['vendor_id']:04x}, PID={info['product_id']:04x}, Name='{info['product_string']}', Path={path}")

                # Use ykman to get the serial number reliably
                try:
                    import subprocess
                    result = subprocess.run(['ykman', 'list', '--serials'], capture_output=True, text=True, check=True)
                    serials = [s for s in result.stdout.strip().split('\n') if s]
                    if not serials:
                        print("Warning: ykman found a key but did not return a serial number.")
                        continue # Skip to the next device

                    # For simplicity, we'll assume the first serial found is the one just plugged in.
                    # A more complex system might need to track which serials are already known.
                    serial_number = serials[0]
                    print(f"Successfully retrieved serial number via ykman: {serial_number}")

                    # Call the backend for verification for each connected client
                    for client, token in connected_clients.items():
                        if token:
                            try:
                                payload = {
                                    'serial_number': serial_number,
                                    'auth_token': token
                                }
                                response = requests.post(FLASK_API_URL, json=payload, timeout=5)
                                print(f"Notified Flask for verification: User token {token[:10]}..., SN {serial_number}. Response: {response.status_code} - {response.text}")
                            except requests.exceptions.RequestException as e:
                                print(f"Failed to notify Flask for verification: {e}")
                        else:
                            print(f"Skipping notification for unauthenticated client.")

                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    print(f"Error running ykman to get serial number: {e}")
                
                known_hid_security_keys[path] = info # Add to our tracked list of connected FIDO keys

        disconnections_found_this_cycle = False
        # --- Detect newly disconnected FIDO devices ---
        disconnected_paths_during_this_scan = [] 
        for path_known in list(known_hid_security_keys.keys()): # Iterate over a copy of keys for safe modification
            if path_known not in current_active_fido_devices_in_this_scan: # A known device is no longer in the current scan
                disconnected_paths_during_this_scan.append(path_known)
        
        if disconnected_paths_during_this_scan:
            disconnections_found_this_cycle = True
            for path_disconnected in disconnected_paths_during_this_scan:
                disconnected_info = known_hid_security_keys.pop(path_disconnected, {}) # Remove from known and get its info
                print(f"Python hid_security_key_monitor: FIDO Security Key Disconnected: Path={path_disconnected}, VID={disconnected_info.get('vendor_id', 'N/A'):04x}, PID={disconnected_info.get('product_id', 'N/A'):04x}")
                
                # The disconnection event can still be broadcast, as the frontend
                # will now handle the logic to restrict models if necessary.
                await send_to_all({
                    "event": "SECURITY_KEY_HID_DISCONNECTED",
                    "path": path_disconnected,
                    "vendorId": f"{disconnected_info.get('vendor_id', 0):04x}",
                    "productId": f"{disconnected_info.get('product_id', 0):04x}"
                })
        
        if not new_connections_found_this_cycle and not disconnections_found_this_cycle:
            # print("Python hid_security_key_monitor: Still scanning for FIDO keys... (no changes detected)") # Optional
            pass
            
async def handler(websocket):  # Single argument for websockets v15+
    remote_addr_info = websocket.remote_address
    client_id_str = "unknown_client"
    if isinstance(remote_addr_info, tuple) and len(remote_addr_info) >= 2:
        client_id_str = f"{remote_addr_info[0]}:{remote_addr_info[1]}"  # Use first two elements
    elif isinstance(remote_addr_info, (str, bytes)):
        client_id_str = str(remote_addr_info)

    print(f"Python Handler: Client {client_id_str} connected.")
    # Add client to the dictionary with a placeholder for the token
    connected_clients[websocket] = None
    print(f"Python Handler: connected_clients now has {len(connected_clients)} client(s).")
    try:
        # The first message from the client should be an auth message
        async for message in websocket:
            print(f"Python Handler: Client {client_id_str} sent message: {message}")
            try:
                data = json.loads(message)
                if data.get('type') == 'auth' and 'token' in data:
                    # Associate the token with this client connection
                    connected_clients[websocket] = data['token']
                    print(f"Authenticated client {client_id_str} with token: {data['token'][:10]}...")
                    
                    # After auth, send initial state
                    print(f"Python Handler: Sending initial state to client {client_id_str}.")
                    if known_usb_drives:
                        await websocket.send(json.dumps(
                            {"event": "NORMAL_USB_CONNECTED", "drive": list(known_usb_drives)[0], "initial_state": True}))
                    else:
                        await websocket.send(json.dumps({"event": "NORMAL_USB_DISCONNECTED", "initial_state": True}))
                    
                    for path, info in known_hid_security_keys.items():
                        await websocket.send(json.dumps({
                            "event": "SECURITY_KEY_HID_CONNECTED",
                            "vendorId": f"{info['vendor_id']:04x}",
                            "productId": f"{info['product_id']:04x}",
                            "path": path,
                            "initial_state": True
                        }))
                    print(f"Python Handler: Initial state sent to client {client_id_str}.")

                else:
                    print(f"Warning: Received non-auth message from {client_id_str} before authentication.")

            except json.JSONDecodeError:
                print(f"Error: Could not decode JSON message from {client_id_str}")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"Python Handler: Client {client_id_str} connection closed normally. Code: {e.code}, Reason: {e.reason}")
    except websockets.exceptions.ConnectionClosedOK as e:
        print(f"Python Handler: Client {client_id_str} connection closed OK. Code: {e.code}, Reason: {e.reason}")
    except Exception as e:
        print(f"Python Handler: Error with client {client_id_str}: {type(e).__name__} - {e}")
    finally:
        print(f"Python Handler: Client {client_id_str} finalizing. Removing from connected_clients.")
        if websocket in connected_clients:
            del connected_clients[websocket]
        print(
            f"Python Handler: connected_clients now has {len(connected_clients)} client(s) after removal of {client_id_str}.")


async def main():
    print("Python main: Starting USB monitor task...")
    usb_monitor_task = asyncio.create_task(usb_monitor())
    print("Python main: Starting HID Security Key monitor task...")
    hid_monitor_task = asyncio.create_task(hid_security_key_monitor())
    
    print("Python main: Starting WebSocket server...")
    server = await websockets.serve(handler, HOST, PORT)
    print(f"Python main: WebSocket server started on ws://{HOST}:{PORT}")
    await server.wait_closed()
    print("Python main: Server wait_closed completed. Cancelling monitor tasks.")
    usb_monitor_task.cancel()
    hid_monitor_task.cancel()
    try:
        await usb_monitor_task
    except asyncio.CancelledError:
        print("Python main: USB Monitor task successfully cancelled.")
    try:
        await hid_monitor_task
    except asyncio.CancelledError:
        print("Python main: HID Security Key Monitor task successfully cancelled.")

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