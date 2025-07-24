# Project Brief: Argus AI Secure POC

## 1. Project Goal

The primary goal of this project is to build a Proof of Concept (POC) for a secure AI chat application named "Argus AI". The application must demonstrate a robust security architecture, focusing on multi-factor authentication (MFA) using hardware security keys (like YubiKeys) and implementing role-based access control (RBAC) for both application features and AI model access.

## 2. Core Features

-   **User Authentication:** Secure user login with username/password and mandatory security key integration.
-   **AI Chat Interface:** A functional chat interface where users can interact with different AI models.
-   **Model Access Control:** Access to certain advanced AI models is restricted and should only be available when a user's registered security key is physically connected.
-   **Admin Dashboard:** A comprehensive dashboard for administrators to manage users, security keys, and monitor system-wide security events.
-   **Security Key Management:** Admins can register, deactivate, reassign, and audit security keys for users.
-   **Real-time USB Detection:** A background service that detects the connection and disconnection of security keys and updates the frontend in real-time.

## 3. Key Technical Requirements

-   **Backend:** Python (Flask)
-   **Frontend:** Next.js (TypeScript, React)
-   **Database:** PostgreSQL
-   **Real-time Communication:** WebSockets for communication between the USB detector and the frontend.
-   **Security:**
    -   Implementation of FIDO2/WebAuthn for security key authentication.
    -   RBAC for differentiating between regular users and administrators.
    -   Secure handling of authentication tokens and sessions.
    -   Detailed audit logging for all critical security events.

## 4. Current Challenge

The USB detection service (`usb_detector.py`) correctly identifies when a security key is plugged in and grants access to restricted AI models. However, it does so for *any* security key, not just the one registered to the currently logged-in user. The immediate task is to rectify this security flaw by ensuring key ownership is verified before granting elevated privileges.