# System Patterns: Argus AI Secure

## Architecture Overview
The application follows Next.js 13+ App Router architecture with a clear separation of concerns:

### Core Patterns

1. **Route Structure**
```
app/
├── login/         # Authentication routes
├── signup/
└── dashboard/     # Protected routes
    ├── security/
    ├── locked-accounts/
    ├── audit-logs/
    ├── users/
    └── settings/
```

2. **Component Organization**
```
components/
├── ui/           # Base UI components
├── data-table/   # Data display components
└── [feature]/    # Feature-specific components
```

## Design Patterns

### 1. Component Architecture
- Atomic design principles with shared UI components
- Data table abstraction for consistent data display
- Compound components for complex UI patterns

### 2. State Management
- Custom store implementation for global state
- React hooks for local state management
- Server-side data fetching using Next.js patterns

### 3. Security Implementation
- WebAuthn integration for passwordless authentication
- Role-based access control
- Audit logging for security events
- Locked account management system

### 4. AI Integration
- Provider-based AI service architecture
- Tool-based AI capabilities
- Chat interface for AI interactions

## Technical Decisions

1. **UI Framework**
- shadcn/ui for consistent component base
- Custom styling with Tailwind CSS
- Responsive design patterns

2. **Data Handling**
- Type-safe data management with TypeScript
- Data table abstractions for security records
- Efficient data fetching and caching

3. **Authentication Flow**
- WebAuthn for primary authentication
- Session management
- Security key registration and verification

4. **Performance Patterns**
- Component-level code splitting
- Optimized data fetching
- Efficient state management