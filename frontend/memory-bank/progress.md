# Project Progress: Argus AI Secure POC

*Last Updated: 2025-07-24*

## 1. What Works (Current State)

-   **User Authentication:** Users can register (via admin) and log in with username/password.
-   **Admin Dashboard:** A functional dashboard exists for managing users and viewing security keys. Admins can perform CRUD operations on users and keys.
-   **Basic USB Detection:** The `usb_detector.py` script successfully detects the connection and disconnection of FIDO/HID security keys.
-   **Real-time Frontend Updates (Flawed):** The frontend correctly receives WebSocket messages from the detector and updates the available AI models in real-time.
-   **Security Key Registration:** The backend flow for registering a security key using WebAuthn and associating it with a user is functional. The `SecurityKey` table correctly stores device details, including the `serial_number`.

## 2. What's Left to Build (Immediate Tasks)

The core focus is to implement the secure key ownership verification flow.

-   **[ ] Backend:**
    -   [ ] Create a new API endpoint (`/api/verify-key-ownership`) in `app.py`.
    -   [ ] Implement the ownership verification logic in the new endpoint.
    -   [ ] Integrate Flask-SocketIO for targeted messaging to the frontend.
-   **[ ] Frontend:**
    -   [ ] Pass the user's `authToken` to the `usb_detector.py` WebSocket server upon connection.
    -   [ ] Remove the old logic that reacts to generic `SECURITY_KEY_...` events.
    -   [ ] Add new logic to handle user-specific events from the backend (`MODELS_UNLOCKED`, `KEY_MISMATCH_ERROR`).
-   **[ ] USB Detector:**
    -   [ ] Modify the WebSocket server to accept and store the `authToken` for each client connection.
    -   [ ] Update the HID monitoring loop to extract the `serial_number` from the device info.
    -   [ ] Replace the generic WebSocket broadcast with a targeted API call to the new backend endpoint.

## 3. Known Issues & Blockers

-   **Critical Security Flaw:** The primary issue being addressed. Model access is granted to any user who plugs in any FIDO key.
-   **No Serial Number Extraction (Yet):** The `usb_detector.py` script currently only extracts `vendor_id` and `product_id`. The logic to get the `serial_number` from the `hid.device_info` needs to be added. This is a potential blocker if the `hid` library cannot reliably provide the serial number for the target devices. (Note: Research indicates this is possible and should not be a blocker).
-   **Communication Mismatch:** The backend uses Flask-SocketIO, while the frontend's connection to the detector uses the native WebSocket API. The new flow will require the frontend to also establish a Socket.IO connection with the backend to receive the targeted verification results.

## 4. Evolution of Project Decisions

-   **Initial Idea:** Have the USB detector be a simple, dumb broadcaster.
-   **Realization:** This is insecure as it lacks user context.
-   **Current Decision:** Evolve the architecture to make the backend the central authority for real-time access control. The detector's role is minimized to simply reporting hardware events to the backend, which then makes the decisions and communicates with the appropriate client. This is a more robust and secure pattern.