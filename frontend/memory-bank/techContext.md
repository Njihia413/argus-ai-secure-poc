# Tech Context: Argus AI Secure POC

## 1. Frontend

-   **Framework:** Next.js 14 with App Router
-   **Language:** TypeScript
-   **UI Components:** `shadcn/ui` and `tailwindcss`
-   **State Management:** React Hooks (`useState`, `useEffect`, `useRef`). No external state management library like Redux or Zustand is currently in use.
-   **API Communication:**
    -   `@ai-sdk/react` for AI chat interactions.
    -   Standard `fetch` API for other backend communication.
-   **Real-time:** Native Browser `WebSocket` API to connect to the `usb_detector.py` script.
-   **Authentication:** `sessionStorage` is used to persist user data and the session token on the client-side.

## 2. Backend

-   **Framework:** Flask
-   **Language:** Python
-   **Database ORM:** SQLAlchemy
-   **Database Migrations:** Flask-Migrate (which uses Alembic).
-   **API:** Standard RESTful API endpoints.
-   **Real-time:** Flask-SocketIO is available but is currently only used for a YubiKey detection feature in the admin dashboard, not for the main chat model-switching logic. The primary real-time channel for the chat page is the separate WebSocket server in `usb_detector.py`.
-   **Security Key Logic:** The `fido2` library is used for handling WebAuthn ceremonies.

## 3. USB Detector

-   **Language:** Python
-   **Core Libraries:**
    -   `websockets`: To run the WebSocket server that the frontend connects to.
    -   `psutil`: For detecting general removable USB drives (a secondary feature).
    -   `hid` (or `hidapi`): The crucial library for enumerating HID devices to find security keys. This is a low-level library that provides device path, vendor ID, and product ID.
    -   `requests`: To make internal API calls to the Flask backend.
-   **Execution:** This is a standalone script intended to be run as a persistent background process on the user's local machine. It is not part of the Flask application server.

## 4. Key Constraints & Considerations

-   **Decoupled Detector:** The `usb_detector.py` script is completely decoupled from the Flask application's user session management. It has no direct access to user information or authentication state. This is the primary technical constraint driving the need for the proposed architecture change.
-   **WebSocket vs. Socket.IO:** The frontend uses the native `WebSocket` API to talk to the `usb_detector.py` script. The backend has `Flask-SocketIO`. The new implementation will need to bridge this gap. The most direct path is to have the detector call a REST endpoint on the backend, and the backend can then use Socket.IO to talk back to the specific user on the frontend.
-   **Serial Number Access:** The `hid` library in `usb_detector.py` does not natively provide the *serial number* for all devices; it reliably provides `vendor_id`, `product_id`, and `path`. The `ykman` CLI tool is used in the backend to get the serial number, but this is for admin-side registration. The `usb_detector.py` script must be updated to extract the serial number directly if possible, or we must rely on another identifier. **Correction:** The `hid.enumerate()` function *can* provide a serial number string if the device exposes one. This will be the key to the new implementation.
-   **Database Schema:** The `SecurityKey` table in the database already has a `serial_number` column, which is populated during the admin-driven registration process. This is perfect for the new verification logic.