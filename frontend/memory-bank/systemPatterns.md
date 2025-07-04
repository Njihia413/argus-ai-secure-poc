# System Patterns: Argus AI Secure

## Architecture Overview
The application follows Next.js 13+ App Router architecture with a clear separation of concerns:

### Core Patterns

1.  **Route Structure**
    ```
    app/
    ├── page.tsx       # Main landing page
    ├── login/         # Authentication routes
    ├── signup/
    └── dashboard/     # Protected routes
        ├── security/
        ├── locked-accounts/
        ├── audit-logs/
        ├── users/
        └── settings/
        └── system-configuration/
        └── emergency-actions/
    ```

2.  **Component Organization**
    ```
    components/
    ├── ui/           # Base UI components (including Dialog for confirmations, Sidebar, Tooltip)
    ├── data-table/   # Data display components (e.g., locked-accounts-data-table.tsx)
    ├── app-sidebar.tsx # Application-specific sidebar implementation
    └── [feature]/    # Feature-specific components
    ```

## Design Patterns

### 1. Component Architecture
-   Atomic design principles with shared UI components.
-   Data table abstraction for consistent data display ([`src/components/data-table/data-table.tsx`](src/components/data-table/data-table.tsx:1)):
    -   Wrapped in `CardContent` for layout.
    -   Supports a `toolbar` prop for custom filter controls (e.g., search input, dropdowns) to be rendered above the table.
    -   Includes built-in pagination controls, and supports server-side pagination via `pageCount` prop and `manualPagination: true` option.
    -   Standardized "Action" column header for action buttons.
    -   Consistent button styling (e.g., black background for primary actions).
    -   Confirmation dialogs (`shadcn/ui Dialog`) for critical actions within table rows (e.g., "Unlock Account"), styled with application's primary font (`font-montserrat`) and consistent sizing (`sm:max-w-[425px]`).
    -   Selective display of columns based on relevance (e.g., "Successful Attempts" column removed where not critical).
-   Compound components for complex UI patterns.
-   **Sidebar Architecture (`src/components/app-sidebar.tsx` & `src/components/ui/sidebar.tsx`):**
    -   Utilizes a context (`SidebarContext`) for managing expanded/collapsed state.
    -   Supports `collapsible="icon"` mode, showing only icons when collapsed.
    -   Integrates with `Tooltip` components from `shadcn/ui` to display item names on hover in collapsed mode.
    -   Conditionally renders text labels based on the sidebar's state, with specific classes (`opacity-0 w-0 hidden`) to ensure proper hiding and layout in collapsed mode.
    -   Applies `justify-center` to `SidebarMenuButton` and its child `<a>` tag when collapsed to aid icon centering.
    -   Active sidebar links (`SidebarMenuButton` with `data-[active=true]`) are styled with `bg-primary`, `text-primary-foreground`, and `rounded-xl` via `sidebarMenuButtonVariants` in `src/components/ui/sidebar.tsx`.
-   **Interactive Charts (e.g., Login Attempts in [`src/app/dashboard/page.tsx`](src/app/dashboard/page.tsx:1)):**
    -   Utilize shadcn `ChartContainer` and associated components (`ChartTooltip`, `ChartLegend`, `ChartLegendContent`) for consistent styling and interactivity.
    -   Employ `ChartConfig` to define series labels and colors (e.g., `color: "var(--chart-2)"` or specific hex values like `#8B5CF6`).
    -   Use shadcn `Select` component for time-range filtering, updating a state variable that triggers data re-fetching.
    -   Structure within a `Card` component, with `CardHeader` for title, description, and filters, and `CardContent` for the `ChartContainer`.
    -   Employ `<defs>` with `<linearGradient>` for area fill opacity.
    -   Omit explicit `<YAxis />` to allow Recharts to auto-configure based on data, for better visual balance.
    -   Use `stackId` on `<Area>` components for stacked area charts when appropriate.

### 2. State Management
-   React `useState` for local component state (e.g., dialog open/closed, loading states for actions).
-   Custom store implementation for global state.
-   Server-side data fetching using Next.js patterns.
-   **State Persistence**: Zustand's `persist` middleware is used to save the authentication state to `sessionStorage`, ensuring it survives page reloads. The application correctly handles the asynchronous rehydration of this state to prevent race conditions.

### 3. Security Implementation
-   WebAuthn integration for passwordless authentication.
-   Role-based access control.
-   **Comprehensive Audit Logging System:**
    -   **Backend Model (`AuditLog` in [`../backend/app.py`](../backend/app.py:1)):**
        -   Fields: `id`, `timestamp`, `user_id` (affected user), `performed_by_user_id` (actor), `action_type`, `target_entity_type`, `target_entity_id`, `details` (contextual info, IP, params), `status` (SUCCESS/FAILURE).
        -   Captures a wide range of system events including user authentication, security key operations, user management, and administrative actions.
    -   **Logging Mechanism:**
        -   Centralized `log_system_event` helper function in the backend for creating audit entries.
        -   Integrated into all relevant API endpoints to ensure consistent and thorough logging.
    -   **API Endpoint (`/api/system-audit-logs`):**
        -   Provides paginated and filterable access to all system audit logs (admin-only).
        -   Supports filtering by user, performer, action type, status, target entity, and date range.
    -   **Frontend Display ([`src/app/dashboard/audit-logs/page.tsx`](src/app/dashboard/audit-logs/page.tsx:1)):**
        -   Dedicated page for viewing system audit logs.
        -   Utilizes the generic `DataTable` component with updated columns (`action_type`, `status`, `user_username`, `performed_by_username`, etc.) and filtering capabilities.
-   Locked account management system (manual admin unlock with confirmation step, locks at 5 attempts, `failed_login_attempts` are reset to 0 upon admin unlock, `unlocked_by` stores admin username, includes check for admin's username before unlock).
-   **Secure Admin Context (New Pattern)**:
    -   **Backend**: A new `authentication_level` field in the `AuthenticationSession` model ([`../backend/app.py`](../backend/app.py:195)) tracks the method of authentication for the current session (e.g., `password_only`, `direct_key_auth`). This level is set upon successful login and returned to the client.
    -   **Frontend**: The `authentication_level` is stored in the global Zustand store ([`src/app/utils/store.ts`](src/app/utils/store.ts:1)).
    -   **Conditional UI**: The application sidebar ([`src/components/app-sidebar.tsx`](src/components/app-sidebar.tsx:1)) uses this state to conditionally render a "Secure Admin" menu, which is only visible if the user has the `admin` role AND has an `authentication_level` indicating they have used a security key for the current session.
    -   **System State Management**: A new `SystemState` model in the backend allows for storing global application settings, such as the "System Lockdown" status. Secure endpoints are provided to modify this state.

### 4. AI Integration
-   Provider-based AI service architecture.
-   Tool-based AI capabilities.
-   Chat interface for AI interactions ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)).
-   Dynamic AI model availability based on external events (e.g., USB connection) communicated via WebSocket from a local helper application.

### 5. User Interaction
-   Use of `shadcn/ui Dialog` components to implement confirmation modals for sensitive operations, ensuring consistent styling (font, size) with the rest of the application.
-   Clear visual feedback during asynchronous operations (e.g., "Unlocking..." button text).

### 6. Local Hardware/System Interaction (New Pattern)
-   **Problem:** Browser limitations prevent direct access to certain system-level hardware events (e.g., generic USB plug/unplug).
-   **Solution:** Employ a lightweight local helper application (e.g., Python script [`../backend/usb_detector.py`](../backend/usb_detector.py:1)) that runs on the user's machine.
    -   The helper application ([`../backend/usb_detector.py`](../backend/usb_detector.py:1)) has the necessary permissions to detect system events like generic USB connections and, more specifically, HID FIDO security key connect/disconnect events (using the `hid` library).
    -   It hosts a WebSocket server (e.g., on `ws://localhost:[PORT]`).
-   **Communication:** The frontend application ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) acts as a WebSocket client, connecting to the local helper.
    -   The helper sends messages (e.g., `NORMAL_USB_CONNECTED`, `SECURITY_KEY_HID_CONNECTED`, `SECURITY_KEY_HID_DISCONNECTED`) to the frontend upon event detection.
    -   The frontend reacts to these messages to update UI or application state (e.g., changing available AI models).
-   **Considerations:**
    -   Requires user to run the local helper application separately.
    -   Error handling for helper connection status (e.g., helper not running, connection lost with robust client-side reconnection attempts).
    -   Security: WebSocket server in helper should ideally only bind to `localhost`.
    -   **Frontend State Handling for WebSockets: To ensure WebSocket event handlers (like `onmessage` in [`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) access the latest React state values (which can be stale in closures), a pattern of using `useRef` to mirror the relevant state (e.g., `hidKeyRef` for `hidKey` state) is employed. The event handler then reads from `ref.current` for conditional logic.**

### 7. Theming Pattern (New)
-   **Library:** `next-themes` is used for managing theme state (light, dark, system).
-   **Provider:** A `src/components/theme-provider.tsx` (with corrected `ThemeProviderProps` import) wraps the root layout (`src/app/layout.tsx`) to enable theme switching.
-   **CSS Variables:** Theme-specific colors (backgrounds, foregrounds, primary, accent, chart colors) are defined as CSS custom properties in `src/app/globals.css` within `:root` (for light theme) and `.dark` (for dark theme) selectors.
    -   Primary button color (`#2563eb` - blue) is consistent across themes. This is also applied to specific interactive elements like the chat submit button, user messages, and the "Login with Security Key" button's border.
    -   Dark theme background is `#0b0a0a`.
    -   A monochromatic color palette derived from the new primary blue color (`#2563eb`) is defined for charts.
-   **Toggle Component:** A `src/components/theme-toggle-button.tsx` provides a UI for users to switch themes. This button is integrated into the main `src/components/header.tsx` (for chat UI) and directly into `src/app/dashboard/layout.tsx` (for dashboard visibility).
-   **Styling Consistency:**
    -   Base UI components like `src/components/ui/button.tsx` (with updated `outline` variant for blue border/text) and `src/components/ui/input.tsx` are updated to use `rounded-xl` for a consistent look and feel.
    -   Specific components like `src/components/textarea.tsx` (main container) are also updated to `rounded-xl`. The internal submit button remains `rounded-xl` but uses the primary theme color.
    -   "Cancel" buttons across various dialogs are now consistently styled using the updated `variant="outline"`.

## Technical Decisions

1.  **UI Framework**
    -   shadcn/ui for consistent component base, including `Dialog` for modals (styled with `font-montserrat`).
    -   Custom styling with Tailwind CSS.
    -   Responsive design patterns.

2.  **Data Handling**
    -   Type-safe data management with TypeScript.
    -   Data table abstractions for security records ([`src/components/data-table/data-table.tsx`](src/components/data-table/data-table.tsx:1)), featuring a `toolbar` prop for custom filter controls, built-in pagination (with support for server-side pagination via `pageCount` and `manualPagination`), standardized action columns/buttons with confirmation dialogs, and curated column visibility.
    -   Efficient data fetching and caching.

3.  **Authentication Flow**
    -   WebAuthn for primary authentication.
    -   Session management.
    -   Security key registration and verification.

4.  **Performance Patterns**
    -   Component-level code splitting.
    -   Optimized data fetching.
    -   Efficient state management.