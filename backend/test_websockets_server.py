import asyncio
import websockets


async def my_test_handler(websocket):  # Single argument
    print(f"Test Handler: Client connected!")

    # Inspect remote_address directly
    remote_addr_info = websocket.remote_address
    print(f"Test Handler: Raw remote_address info: {remote_addr_info}")
    print(f"Test Handler: Type of remote_address info: {type(remote_addr_info)}")

    # We'll try to construct a client_id string safely
    client_id_str = "unknown_client"
    if isinstance(remote_addr_info, tuple) and len(remote_addr_info) >= 2:
        client_id_str = f"{remote_addr_info[0]}:{remote_addr_info[1]}"
    elif isinstance(remote_addr_info, (str, bytes)):  # For Unix domain sockets or other formats
        client_id_str = str(remote_addr_info)

    print(f"Test Handler: Client ID determined as: {client_id_str}")

    try:
        await websocket.send(f"Hello from Test Server, {client_id_str}!")
        print("Test Handler: Welcome message sent.")

        async for message in websocket:
            print(f"Test Handler: Received message from client ({client_id_str}): {message}")
            await websocket.send(f"Test Server echoes to {client_id_str}: {message}")
    except websockets.exceptions.ConnectionClosedError:
        print(f"Test Handler: Client {client_id_str} connection closed normally.")
    except Exception as e:
        print(f"Test Handler: An error occurred with client {client_id_str}: {type(e).__name__} - {e}")
    finally:
        print(f"Test Handler: Client {client_id_str} disconnected.")


async def main():
    print("Test Server: Starting WebSocket server on ws://localhost:8765")
    server = await websockets.serve(my_test_handler, "localhost", 8765)
    print("Test Server: WebSocket server started successfully.")
    await server.wait_closed()


if __name__ == "__main__":
    print("Test Script: Starting.")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Test Script: Server shutting down.")
    except Exception as e:
        print(f"Test Script: An error occurred in __main__: {type(e).__name__} - {e}")
    finally:
        print("Test Script: Exiting.")

