# Argus AI Secure

Argus AI Secure is a comprehensive, full-stack web application designed for robust security management, user authentication, and access control. It features a Next.js frontend and a Python Flask backend, integrating modern security practices like WebAuthn with AI-assisted operational capabilities.

## Core Features

- **Advanced User Authentication:** Secure login/signup flows with password-based and passwordless (WebAuthn) authentication using security keys.
- **Comprehensive Security Dashboard:** A central hub for monitoring security metrics, managing users, tracking security alerts, and viewing audit logs.
- **Security Key Management:** End-to-end lifecycle management for FIDO2 security keys, including registration, deactivation, reset, and reassignment.
- **Account Lockout System:** Automatically locks user accounts after multiple failed login attempts, with a dedicated interface for administrators to manage and unlock accounts.
- **System-Wide Audit Trail:** Detailed logging of all critical security and system events, providing a clear and searchable history for compliance and investigation.
- **AI-Powered Chat Assistant:** An integrated chat interface that leverages AI models to assist with security-related queries and operations. Model availability can be dynamically enhanced by connecting a security key.
- **Local Hardware Detection:** A local Python helper application detects USB and HID FIDO security key connections, enabling real-time interaction between the user's hardware and the application.

## Technical Stack

### Frontend

- **Framework:** Next.js 15+ (with App Router)
- **Language:** TypeScript
- **UI:** shadcn/ui, Radix UI, Tailwind CSS
- **State Management:** Zustand
- **Data Fetching:** Axios
- **Charting:** Recharts
- **Security:** `@simplewebauthn/browser` for WebAuthn
- **AI:** Vercel AI SDK with Groq

### Backend

- **Framework:** Flask
- **Language:** Python
- **Database:** PostgreSQL with SQLAlchemy ORM and Flask-Migrate
- **Authentication:** FIDO2-lib for WebAuthn server-side validation
- **Real-time Communication:** WebSockets for communication with the local hardware detector.

## Project Structure

The project is organized into two main directories: `frontend/` and `backend/`.

```
.
├── backend/
│   ├── app.py              # Main Flask application, API endpoints
│   ├── requirements.txt    # Python dependencies
│   ├── migrations/         # Database migration scripts
│   └── usb_detector.py     # WebSocket server for hardware detection
│
└── frontend/
    ├── src/
    │   ├── app/            # Next.js routes and pages
    │   ├── components/     # Reusable React components
    │   ├── lib/            # Utility functions and hooks
    │   └── ai/             # AI integration services
    ├── package.json        # Frontend dependencies
    └── memory-bank/        # Project documentation
```

## Getting Started

### Prerequisites

- Node.js (v20.0.0 or higher)
- Python (v3.8 or higher)
- PostgreSQL

### 1. Backend Setup

1.  **Navigate to the backend directory:**
    ```bash
    cd backend
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up the PostgreSQL database:**
    - Create a new database named `argus_ai_secure_poc`.
    - Update the database connection string in [`backend/app.py`](backend/app.py:34) if your configuration is different:
      ```python
      app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://YOUR_USER:YOUR_PASSWORD@localhost/argus_ai_secure_poc'
      ```

5.  **Apply database migrations:**
    ```bash
    flask db upgrade
    ```
    This will create all the necessary tables and the default admin user (`admin`/`admin123`).

6.  **Run the Flask server:**
    ```bash
    flask run
    ```
    The backend API will be running at `http://localhost:5000`.

### 2. Frontend Setup

1.  **Navigate to the frontend directory:**
    ```bash
    cd frontend
    ```

2.  **Install the required Node.js packages:**
    ```bash
    npm install
    ```

3.  **Set up environment variables:**
    - Create a `.env.local` file in the `frontend` directory.
    - Add your Groq API key:
      ```
      GROQ_API_KEY="YOUR_GROQ_API_KEY"
      ```

4.  **Run the Next.js development server:**
    ```bash
    npm run dev
    ```
    The frontend application will be available at `http://localhost:3000`.

### 3. Run the USB Detector (Optional)

To enable dynamic AI model availability based on hardware security key presence, run the local WebSocket server.

1.  **Navigate to the backend directory in a new terminal:**
    ```bash
    cd backend
    ```

2.  **Activate the virtual environment:**
    ```bash
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Run the USB detector script:**
    ```bash
    python usb_detector.py
    ```
    The script will monitor for USB and FIDO device connections and communicate with the frontend.

## Usage

- **Admin Login:** Access the application at `http://localhost:3000/login` and use the default credentials `admin` / `admin123`.
- **User Management:** Navigate to the "Users" section in the dashboard to create, manage, and view user details.
- **Security Key Management:** Register and manage security keys for users through their individual details page.

## System Components

The following diagram illustrates the main components of the Argus AI Secure application and their interactions:

```mermaid
graph TD
    subgraph UI ["User Interface (Frontend)"]
        direction TB
        UI_WebApp[Next.js Web App]
        UI_Dashboard[Admin Dashboard]
        UI_Chat[AI Chat Interface]
        UI_Auth[Login/Signup Pages]
        UI_WebApp -- Manages --> UI_Dashboard
        UI_WebApp -- Contains --> UI_Chat
        UI_WebApp -- Provides --> UI_Auth
    end

    subgraph BE ["Backend Services"]
        direction TB
        BE_Flask[Flask API Server]
        BE_Database[PostgreSQL Database]
        BE_WebAuthn["WebAuthn (FIDO2) Library"]
        BE_Flask -- Uses --> BE_WebAuthn
        BE_Flask -- CRUD --> BE_Database
    end

    subgraph LS ["Local Services"]
        direction TB
        LS_WSServer["USB Detector (WebSocket)"]
        LS_HID[HID/USB Listener]
        LS_WSServer -- Uses --> LS_HID
    end

    subgraph ES ["External Services"]
        direction TB
        ES_AI["AI Provider (Groq)"]
    end

    subgraph U ["Users"]
        direction TB
        U_Admin[Administrator]
        U_User[End User]
        U_Hardware[User's Hardware]
    end

    U_Admin -- Interacts with --> UI_Dashboard
    U_User -- Interacts with --> UI_Auth
    U_User -- Interacts with --> UI_Chat
    U_Hardware -.-> LS_HID

    UI_WebApp -- API Calls --> BE_Flask
    UI_Chat -- API Calls --> ES_AI
    UI_Chat -- WebSocket --> LS_WSServer

    style UI fill:#ccf,stroke:#333,stroke-width:2px
    style BE fill:#cfc,stroke:#333,stroke-width:2px
    style LS fill:#f9f,stroke:#333,stroke-width:2px
    style ES fill:#fcf,stroke:#333,stroke-width:2px
    style U fill:#ffc,stroke:#333,stroke-width:2px
```

## User Journey: Security Key Authentication

The following diagram shows the sequence of events for a user logging in with a security key (WebAuthn).

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend (Next.js)
    participant BE as Backend (Flask)
    participant SK as Security Key

    U->>FE: Enters username and password
    FE->>BE: POST /api/login (credentials)
    BE->>BE: Verifies password against hash
    alt Password Correct
        BE-->>FE: Password verified, requests 2FA
        FE->>U: Prompt for Security Key
        U->>SK: Touches Security Key
        FE->>BE: GET /api/webauthn/login/begin
        BE->>BE: Generate challenge
        BE-->>FE: Return challenge
        FE->>SK: Pass challenge to Security Key
        SK->>SK: Sign challenge with private key
        SK-->>FE: Return signed assertion
        FE->>BE: POST /api/webauthn/login/complete (assertion)
        BE->>BE: Verify assertion with stored public key
        alt Assertion Valid
            BE-->>FE: Authentication successful, return session token
            FE->>U: Redirect to Dashboard
        else Assertion Invalid
            BE-->>FE: Authentication failed
            FE->>U: Show error message
        end
    else Password Incorrect
        BE-->>FE: Invalid credentials
        FE->>U: Show error message
    end
```