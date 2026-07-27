# Argus AI Secure

Argus AI Secure is a comprehensive, full-stack security management platform built on Next.js and Python Flask. It combines zero-trust encrypted file storage, machine-bound hardware authentication (FIDO2/WebAuthn), tiered AI model access, network zone policy enforcement, and fine-grained role-based access control into a single cohesive system.

## Live Deployment

| Service | URL |
|---|---|
| Frontend (Vercel) | https://argus-ai-secure-poc.vercel.app |
| Backend API (Render) | https://argus-ai-secure-poc.onrender.com |
| Backend health check | https://argus-ai-secure-poc.onrender.com/api/health |

> **Note:** The backend runs on Render's free tier, which spins down after ~15 minutes of inactivity. The first request after an idle period may take 30–50 seconds while the instance wakes up. Real-time hardware features (USB detector, machine fingerprinting) require the local detector and are not available on the hosted demo.

## Core Features

- **Advanced User Authentication:** Secure login flows with password-based and passwordless (WebAuthn) two-factor authentication using FIDO2 security keys. Sessions are managed via short-lived tokens with configurable expiry.
- **Comprehensive Security Dashboard:** A central hub with real-time metrics — risk score trends, login attempt history, device statistics, security key adoption funnel, and tier distribution charts.
- **Security Key Management:** End-to-end lifecycle management for FIDO2 security keys, including registration, deactivation, reset, and reassignment. YubiKey-specific details (serial number, firmware version, form factor, FIPS/Sky flags) are automatically extracted during registration.
- **Machine Binding:** Security keys can be restricted to specific machines. A deterministic SHA-256 fingerprint (derived from the machine UUID and OS family) is generated locally and verified server-side during authentication. Per-key policy controls whether binding is required and how many machines are permitted.
- **Account Lockout System:** Automatically locks user accounts after a configurable number of failed login attempts, with a dedicated interface for administrators to review and unlock accounts.
- **System-Wide Audit Trail:** Detailed, searchable logs of all critical security and system events — key registrations, lockdowns, role changes, file operations, and more — for compliance and incident investigation.
- **AI-Powered Chat Assistant:** An integrated streaming chat interface powered by Groq. Available models are gated by the user's current access tier: users with no security key see baseline models; users with an unbound key unlock mid-tier models; users with a machine-bound key unlock the most capable models.
- **Tiered Access Control:** Three access tiers (`none` → `key_unbound` → `key_bound`) gate AI models and registered applications. Tier assignment is dynamic based on the user's current authentication state and hardware presence.
- **Role-Based Access Control (RBAC):** Five canonical roles — `admin`, `it_department`, `manager`, `hr`, `customer_service` — each with configurable permission grants over AI models, registered applications, and admin dashboard sections.
- **Network Zones & Zone Groups:** Define named CIDR ranges with optional security key requirements. Group zones together with registered applications as logical policy units to enforce network-level access rules.
- **Registered Applications:** External services can authenticate via generated API keys and be associated with network zone groups to control where they are accessible from.
- **Encrypted File Storage:** A zero-trust storage system where files are encrypted at rest using AES-256-GCM before being written to either local disk or MinIO S3-compatible object storage. Decryption keys are derived via PBKDF2 from the user's security key ID and a system secret — files are mathematically inaccessible without the physical token. Files can be organised into **Vaults** for logical grouping.
- **Local Hardware Detection:** A local Python WebSocket server monitors USB and HID connections. On security key insertion it extracts YubiKey metadata, computes the machine fingerprint, and posts both to the Flask backend in real time.
- **Emergency Actions:** A dedicated admin page to trigger or lift a system-wide lockdown with a custom message, fully audit-logged.
- **System Configuration:** Maintenance mode toggle with audit logging.
- **Configurable Security Settings:** Session timeout, failed-login threshold, WebAuthn timeout, and password policy (minimum length, uppercase/lowercase/digit/special-character requirements, and expiry interval) are all configurable at runtime from the admin dashboard.

## Technical Stack

### Frontend

| Technology | Version | Purpose |
|---|---|---|
| Next.js | 15.2+ | Framework (App Router, Turbopack dev server) |
| React | 19 | UI runtime |
| TypeScript | 5+ | Type safety |
| Tailwind CSS | 4 | Styling |
| shadcn/ui + Radix UI | — | Accessible component library |
| Vercel AI SDK (`ai`) | ^4.2.5 | Streaming AI integration |
| `@ai-sdk/groq` | ^1.2.1 | Groq provider |
| `@ai-sdk/react` | ^1.2.2 | React hooks for AI streaming |
| Axios | ^1.8.4 | HTTP client |
| socket.io-client | ^4.8.1 | WebSocket (USB detector) |
| `@simplewebauthn/browser` | ^13.1.0 | WebAuthn/FIDO2 client |
| `@tanstack/react-table` | ^8.21.3 | Advanced data tables |
| Recharts | ^2.15.3 | Charts and metrics |
| jsPDF + jspdf-autotable | ^3.0.1 | PDF export (audit logs, reports) |
| motion | ^12.6.2 | Animations |
| Zustand | — | State management |

### Backend

| Technology | Version | Purpose |
|---|---|---|
| Flask | 3.1.1 | Web framework |
| Python | 3.8+ | Runtime |
| PostgreSQL + SQLAlchemy | 2.0.30 | Database and ORM |
| Flask-Migrate / Alembic | 4.1.0 / 1.15.2 | Database migrations |
| fido2 | 2.0.0 | WebAuthn/FIDO2 server-side validation |
| cryptography | >=43.0.0 | AES-256-GCM encryption and PBKDF2 key derivation |
| minio | >=7.2.0 | S3-compatible object storage client |
| Flask-JWT-Extended | 4.6.0 | JWT session tokens |
| Flask-SocketIO | 5.3.6 | WebSocket server |
| Flask-Limiter | 3.9.0 | Rate limiting |
| yubikey-manager | 5.7.2 | YubiKey metadata extraction |
| hidapi | 0.14.0 | HID device communication |
| pyscard | 2.0.7 | Smart card interface |
| psutil | 7.0.0 | Disk and process monitoring |
| websockets | 15.0.1 | Async WebSocket protocol |
| eventlet | 0.33.3 | Concurrency for Flask-SocketIO |

## Project Structure

```
.
├── backend/
│   ├── app.py                  # Main Flask application — all API endpoints and database models
│   ├── file_encryption.py      # AES-256-GCM encryption and PBKDF2 key derivation
│   ├── minio_storage.py        # MinIO S3 object storage wrapper
│   ├── machine_fingerprint.py  # Deterministic SHA-256 machine fingerprint generation
│   ├── usb_detector.py         # Async WebSocket server for USB/HID hardware monitoring
│   ├── requirements.txt        # Python dependencies
│   ├── .env.example            # Environment variable template
│   └── migrations/             # Alembic database migration scripts (27 migrations)
│
└── frontend/
    ├── src/
    │   ├── app/
    │   │   ├── page.tsx                        # Home / landing page with login modal
    │   │   ├── signup/                         # Signup page
    │   │   └── dashboard/
    │   │       ├── page.tsx                    # Main dashboard overview
    │   │       ├── users/                      # User management + detail pages
    │   │       ├── security-keys/              # Security key management + detail pages
    │   │       ├── roles/                      # RBAC role and permission management
    │   │       ├── models/                     # AI model tier configuration
    │   │       ├── applications/               # Registered application management
    │   │       ├── network-zones/              # Network zone CIDR configuration
    │   │       ├── network-zone-groups/        # Zone group and app association
    │   │       ├── secure-files/               # Encrypted file storage and vaults
    │   │       ├── audit-logs/                 # System audit trail
    │   │       ├── security/                   # Security alerts and active sessions
    │   │       ├── settings/                   # Security policy settings
    │   │       ├── emergency-actions/          # System lockdown controls
    │   │       └── system-configuration/       # Maintenance mode
    │   ├── components/                         # Reusable React components
    │   ├── lib/                                # Utility functions and hooks
    │   └── ai/
    │       ├── providers.ts                    # Groq model registration
    │       └── tools.ts                        # AI tool definitions
    ├── package.json
    └── memory-bank/                            # Project documentation
```

## Getting Started

### Prerequisites

- Node.js v20.0.0 or higher
- Python 3.8 or higher
- PostgreSQL
- MinIO (optional — files fall back to local disk storage if not configured)

### 1. Backend Setup

**Navigate to the backend directory and create a virtual environment:**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Configure environment variables** by copying the example file and filling in your values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string, e.g. `postgresql://user:pass@localhost/argus_ai_secure_poc` |
| `SECRET_KEY` | Flask session secret (auto-generated if omitted) |
| `FILE_ENCRYPTION_SECRET` | 32+ byte secret used for PBKDF2 file key derivation |
| `ENCRYPTED_FILES_PATH` | Local path for encrypted file storage fallback |
| `MINIO_ENDPOINT` | MinIO server host:port, e.g. `localhost:9000` |
| `MINIO_ACCESS_KEY` | MinIO access key |
| `MINIO_SECRET_KEY` | MinIO secret key |
| `MINIO_BUCKET` | Bucket name (default: `argus-encrypted-files`) |
| `MINIO_USE_SSL` | `true` / `false` (default: `false`) |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins, e.g. `http://localhost:3000` |
| `FLASK_API_URL` | Backend URL used by the USB detector, e.g. `http://localhost:5000` |

**Apply database migrations:**

```bash
flask db upgrade
```

This creates all tables and seeds a default admin user (`admin` / `admin123`).

**Run the Flask server:**

```bash
flask run
```

The backend API will be available at `http://localhost:5000`.

### 2. Frontend Setup

**Navigate to the frontend directory and install dependencies:**

```bash
cd frontend
npm install
```

**Create `.env.local`** with the following variables:

```env
GROQ_API_KEY="your-groq-api-key"
NEXT_PUBLIC_FLASK_URL="http://localhost:5000"
```

**Start the development server:**

```bash
npm run dev
```

The frontend application will be available at `http://localhost:3000`.

### 3. Run the USB Detector (Optional)

Required for real-time hardware key detection, machine fingerprinting, and dynamic AI model tier upgrades.

```bash
cd backend
source venv/bin/activate
python usb_detector.py
```

The detector runs a WebSocket server on `ws://localhost:12345`. When a FIDO2 security key is inserted, it extracts YubiKey metadata, computes the machine fingerprint, and notifies both the frontend and the Flask backend.

## Available AI Models

Models are seeded automatically on first migration. Access is gated by the user's current authentication tier.

| Model | Minimum Tier |
|---|---|
| `llama-3.1-8b-instant` | `none` (no key required) |
| `llama-3.3-70b-versatile` | `key_unbound` |
| `meta-llama/llama-4-scout-17b` | `key_unbound` |
| `qwen/qwen3-32b` | `key_unbound` |
| `openai/gpt-oss-20b` | `key_bound` (machine-bound key required) |
| `openai/gpt-oss-120b` | `key_bound` (machine-bound key required) |

Tier assignments can be changed at runtime from the **Models** admin page (`/dashboard/models`).

## Usage

- **Admin Login:** Visit `http://localhost:3000` (or the [live frontend](https://argus-ai-secure-poc.vercel.app)) and sign in with `admin` / `admin123`.
- **User Management:** `/dashboard/users` — create, view, and manage user accounts.
- **Security Key Management:** Navigate to a user's detail page to register, deactivate, reset, or reassign security keys.
- **Machine Binding:** On a security key's detail page, configure the binding policy and view or add bound machines.
- **AI Chat:** Click the chat icon to open the assistant. Inserting a security key into the USB detector upgrades the available model tier in real time.
- **Encrypted Files:** `/dashboard/secure-files` — upload, organise into vaults, preview, and download files. Decryption requires the security key that was present at upload time.
- **Network Zones:** `/dashboard/network-zones` and `/dashboard/network-zone-groups` — define CIDR ranges and associate them with registered applications.
- **RBAC:** `/dashboard/roles` — assign granular permissions to each role for models, applications, and admin sections.

## System Components

```mermaid
graph TD
    subgraph UI ["User Interface (Frontend — Next.js)"]
        UI_Auth[Login / Signup]
        UI_Dashboard[Admin Dashboard]
        UI_Chat[AI Chat Interface]
        UI_Files[Secure File Storage]
        UI_Config[System Config & Settings]
    end

    subgraph BE ["Backend Services (Flask)"]
        BE_Flask[Flask API Server]
        BE_WebAuthn[WebAuthn / FIDO2]
        BE_Crypto[AES-256-GCM Encryption]
        BE_DB[(PostgreSQL)]
        BE_Minio[(MinIO Object Storage)]
        BE_Flask --> BE_WebAuthn
        BE_Flask --> BE_Crypto
        BE_Flask --> BE_DB
        BE_Crypto --> BE_Minio
    end

    subgraph LS ["Local Services"]
        LS_WS["USB Detector (WebSocket :12345)"]
        LS_HID[HID / USB Listener]
        LS_FP[Machine Fingerprint]
        LS_WS --> LS_HID
        LS_WS --> LS_FP
    end

    subgraph ES ["External Services"]
        ES_Groq[Groq AI API]
    end

    subgraph U ["Users"]
        U_Admin[Administrator]
        U_User[End User]
        U_HW[Security Key / USB Device]
    end

    U_Admin --> UI_Dashboard
    U_User --> UI_Auth
    U_User --> UI_Chat
    U_HW -.->|detected| LS_HID

    UI_Auth --> BE_Flask
    UI_Dashboard --> BE_Flask
    UI_Files --> BE_Flask
    UI_Config --> BE_Flask
    UI_Chat -->|streaming| ES_Groq
    UI_Chat --> LS_WS
    UI_Auth --> LS_WS
    LS_WS -->|"POST key event + fingerprint"| BE_Flask

    style UI fill:#ccf,stroke:#333,stroke-width:2px
    style BE fill:#cfc,stroke:#333,stroke-width:2px
    style LS fill:#f9f,stroke:#333,stroke-width:2px
    style ES fill:#fcf,stroke:#333,stroke-width:2px
    style U fill:#ffc,stroke:#333,stroke-width:2px
```

## User Journey: Security Key Authentication

```mermaid
sequenceDiagram
    participant U as User
    participant LM as Login Modal
    participant BE as Backend (Flask)
    participant SK as Security Key
    participant WS as USB Detector

    U->>LM: Enters username and password
    LM->>BE: POST /api/login (credentials)
    BE->>BE: Verify password, check account status

    alt User has Security Key
        BE-->>LM: Password verified — return interim auth token
        LM->>U: Prompt for Security Key (2FA)
        U->>SK: Touch Security Key
        WS->>WS: Detect key insertion, compute machine fingerprint
        WS->>BE: POST /api/internal/hid-security-key-event (fingerprint + serial)
        LM->>BE: POST /api/webauthn/login/begin
        BE->>BE: Generate challenge
        BE-->>LM: Return challenge
        LM->>SK: Pass challenge to Security Key
        SK->>SK: Sign challenge with private key
        SK-->>LM: Return signed assertion
        LM->>BE: POST /api/webauthn/login/complete (assertion)
        BE->>BE: Verify assertion with stored public key

        alt Machine binding required
            BE->>BE: Check machine fingerprint vs bound machines
            alt Fingerprint matches
                BE-->>LM: Binding OK — return final session token
                LM->>U: Redirect to Dashboard / Chat
            else Fingerprint not bound
                BE-->>LM: Machine not authorised
                LM->>U: Show binding error
            end
        else No machine binding required
            BE-->>LM: Return final session token
            LM->>U: Redirect to Dashboard / Chat
        end

    else User has NO Security Key
        BE-->>LM: Authentication successful — return session token
        LM->>U: Redirect to Dashboard / Chat
    else Password Incorrect
        BE-->>LM: Invalid credentials
        LM->>U: Show error message
    end
```
