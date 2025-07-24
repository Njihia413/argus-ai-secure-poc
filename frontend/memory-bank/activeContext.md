# Active Context: Secure USB Detection Flow

*Last Updated: 2025-07-24*

## 1. Current Focus

The immediate and critical task is to fix the security vulnerability in the USB detection mechanism. The system currently grants access to premium AI models upon the connection of *any* FIDO-compliant security key, rather than verifying that the key belongs to the currently authenticated user.

## 2. Problem Summary

-   **Source of Flaw:** The `usb_detector.py` script is decoupled from user sessions. It broadcasts a generic "key connected" event via a basic WebSocket server to all connected frontends.
-   **Symptom:** Any user can gain access to all models by plugging in any YubiKey, even one not registered in the system or registered to a different user.
-   **Goal:** Implement a verification step where the backend validates that the serial number of the connected key is registered to the specific user who is logged into the session where the key was detected.

## 3. Key Decisions & Proposed Changes

1.  **Shift of Authority:** The `backend` (Flask app) will become the single source of truth for authorizing model access based on key connection. The `usb_detector.py` script will be demoted to a simple hardware event reporter.
2.  **User Identification:** The `frontend` must pass user-identifying information to the `usb_detector.py` script upon establishing a WebSocket connection. The user's `authToken` (session token) is the ideal candidate for this.
3.  **New Backend Endpoint:** A new API endpoint will be created on the Flask backend, e.g., `/api/verify-key-ownership`. This endpoint will accept a security key's `serial_number` and a user's `authToken`.
4.  **Serial Number Extraction:** The `usb_detector.py` script must be modified to extract the `serial_number` from the `hid.enumerate()` device info. This is a critical change, as `vendor_id` and `product_id` are not unique enough for this verification.
5.  **Communication Flow Change:**
    -   The direct WebSocket message from the detector to the frontend that unlocks models will be **removed**.
    -   The detector will now call the new backend endpoint with the `serial_number` and the user's `authToken`.
    -   The backend will perform the ownership check.
    -   The backend will then need to communicate the result back to the *correct* user's frontend session. Using a targeted WebSocket event (e.g., via Flask-SocketIO rooms) is the preferred pattern.

## 4. Next Steps (Implementation Plan)

The following is the high-level plan to implement this change:

1.  **Backend:** Create the new `/api/verify-key-ownership` endpoint in `app.py`.
2.  **Backend:** Implement the logic within this endpoint to validate the token, find the key by serial number, and check for ownership.
3.  **Backend:** Integrate Flask-SocketIO to allow the backend to push targeted messages to the frontend.
4.  **Frontend:** Modify the `ChatPage` to send the `authToken` when it connects to the `usb_detector.py` WebSocket server.
5.  **Frontend:** Modify the `ChatPage` to handle new, user-specific WebSocket events from the backend (e.g., `MODELS_UNLOCKED`, `KEY_MISMATCH_ERROR`).
6.  **USB Detector:** Update `usb_detector.py` to receive and store the `authToken` per connection.
7.  **USB Detector:** Update `usb_detector.py` to extract the `serial_number` from the HID device info.
8.  **USB Detector:** Change the `hid_security_key_monitor` to call the new backend endpoint instead of sending a generic WebSocket message.

This structured approach ensures that each component is modified correctly to support the new, secure verification flow.