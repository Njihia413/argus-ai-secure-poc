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
    ├── ui/           # Base UI components (including Dialog for confirmations, Sidebar, Tooltip)
    ├── data-table/   # Data display components (e.g., locked-accounts-data-table.tsx)
    ├── app-sidebar.tsx # Application-specific sidebar implementation
    └── [feature]/    # Feature-specific components
    ```

## Design Patterns

### 1. Component Architecture
-   Atomic design principles with shared UI components.
-   Data table abstraction for consistent data display:
    -   Wrapped in `CardContent` for layout.
    -   Supports a `toolbar` prop for custom filter controls (e.g., search input, dropdowns) to be rendered above the table.
    -   Includes built-in pagination controls.
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

### 2. State Management
-   React `useState` for local component state (e.g., dialog open/closed, loading states for actions).
-   Custom store implementation for global state.
-   Server-side data fetching using Next.js patterns.

### 3. Security Implementation
-   WebAuthn integration for passwordless authentication.
-   Role-based access control.
-   Audit logging for security events.
-   Locked account management system (manual admin unlock with confirmation step, locks at 5 attempts, `failed_login_attempts` persist through unlock and increment even if account is already locked, `unlocked_by` stores admin username).

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
-   **Solution:** Employ a lightweight local helper application (e.g., Python script `../backend/usb_detector.py`) that runs on the user's machine.
    -   The helper application has the necessary permissions to detect these system events.
    -   It hosts a WebSocket server (e.g., on `ws://localhost:[PORT]`).
-   **Communication:** The frontend application ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) acts as a WebSocket client, connecting to the local helper.
    -   The helper sends messages to the frontend upon event detection (e.g., `NORMAL_USB_CONNECTED`).
    -   The frontend reacts to these messages to update UI or application state (e.g., changing available AI models).
-   **Considerations:**
    -   Requires user to run the local helper application separately.
    -   Error handling for helper connection status (e.g., helper not running, connection lost).
    -   Security: WebSocket server in helper should ideally only bind to `localhost`.

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
    -   Specific components like `src/components/textarea.tsx` (main container) are also updated to `rounded-xl`. The internal submit button remains `rounded-full` but uses the primary theme color.
    -   "Cancel" buttons across various dialogs are now consistently styled using the updated `variant="outline"`.

## Technical Decisions

1.  **UI Framework**
    -   shadcn/ui for consistent component base, including `Dialog` for modals (styled with `font-montserrat`).
    -   Custom styling with Tailwind CSS.
    -   Responsive design patterns.

2.  **Data Handling**
    -   Type-safe data management with TypeScript.
    -   Data table abstractions for security records, featuring a `toolbar` prop for custom filter controls, built-in pagination, standardized action columns/buttons with confirmation dialogs, and curated column visibility.
    -   Efficient data fetching and caching.

3.  **Authentication Flow**
    -   WebAuthn for primary authentication.
    -   Session management.
    -   Security key registration and verification.

4.  **Performance Patterns**
    -   Component-level code splitting.
    -   Optimized data fetching.
    -   Efficient state management.