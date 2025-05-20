# System Patterns: Argus AI Secure

## Architecture Overview
The application follows Next.js 13+ App Router architecture with a clear separation of concerns:

### Core Patterns

1.  **Route Structure**
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

2.  **Component Organization**
    ```
    components/
    ├── ui/           # Base UI components (including Dialog for confirmations)
    ├── data-table/   # Data display components (e.g., locked-accounts-data-table.tsx)
    └── [feature]/    # Feature-specific components
    ```

## Design Patterns

### 1. Component Architecture
-   Atomic design principles with shared UI components.
-   Data table abstraction for consistent data display:
    -   Wrapped in `CardContent` for layout.
    -   Single global search input (e.g., "Search..." with `max-w-md`).
    -   Standardized "Action" column header for action buttons.
    -   Consistent button styling (e.g., black background for primary actions).
    -   Confirmation dialogs (`shadcn/ui Dialog`) for critical actions within table rows (e.g., "Unlock Account"), styled with application's primary font (`font-montserrat`) and consistent sizing (`sm:max-w-[425px]`).
    -   Selective display of columns based on relevance (e.g., "Successful Attempts" column removed where not critical).
-   Compound components for complex UI patterns.

### 2. State Management
-   React `useState` for local component state (e.g., dialog open/closed, loading states for actions).
-   Custom store implementation for global state.
-   Server-side data fetching using Next.js patterns.

### 3. Security Implementation
-   WebAuthn integration for passwordless authentication.
-   Role-based access control.
-   Audit logging for security events.
-   Locked account management system (manual admin unlock with confirmation step).

### 4. AI Integration
-   Provider-based AI service architecture.
-   Tool-based AI capabilities.
-   Chat interface for AI interactions.

### 5. User Interaction
-   Use of `shadcn/ui Dialog` components to implement confirmation modals for sensitive operations, ensuring consistent styling (font, size) with the rest of the application.
-   Clear visual feedback during asynchronous operations (e.g., "Unlocking..." button text).

## Technical Decisions

1.  **UI Framework**
    -   shadcn/ui for consistent component base, including `Dialog` for modals (styled with `font-montserrat`).
    -   Custom styling with Tailwind CSS.
    -   Responsive design patterns.

2.  **Data Handling**
    -   Type-safe data management with TypeScript.
    -   Data table abstractions for security records, featuring global search (e.g., `Input` with `max-w-md`), standardized action columns/buttons with confirmation dialogs, and curated column visibility.
    -   Efficient data fetching and caching.

3.  **Authentication Flow**
    -   WebAuthn for primary authentication.
    -   Session management.
    -   Security key registration and verification.

4.  **Performance Patterns**
    -   Component-level code splitting.
    -   Optimized data fetching.
    -   Efficient state management.