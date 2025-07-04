# Active Context: Argus AI Secure

## Current Focus
The primary focus has been the implementation of a secure administrative context, allowing for privileged actions only after a high-security login. This involved backend session management, frontend state handling, and the creation of new secure pages.

### 1. Secure Admin Context and Controls (New Feature)
*   **Backend ([`../backend/app.py`](../backend/app.py:1)):**
    *   Added `has_elevated_access` to the login response for admins using a security key.
    *   Added `SystemStatus` and `SystemConfiguration` models to manage emergency lockdown and maintenance mode.
    *   Implemented an `@elevated_admin_required` decorator to protect sensitive endpoints.
    *   Created API endpoints for emergency actions (`/api/emergency/status`, `/api/emergency/toggle-lockdown`) and system configuration (`/api/system-configuration`).
    *   Modified the login endpoint to check for maintenance mode.
*   **Frontend State ([`src/app/utils/store.ts`](src/app/utils/store.ts:1)):**
    *   The Zustand store now includes `hasElevatedAccess` to manage the elevated access state.
    *   Implemented `persist` middleware to save the `hasElevatedAccess` state to `sessionStorage`.
*   **Frontend UI:**
    *   The dashboard sidebar ([`src/components/app-sidebar.tsx`](src/components/app-sidebar.tsx:1)) now conditionally renders "Emergency Actions" and "System Configuration" menu items based on the `hasElevatedAccess` state.
    *   Created the "Emergency Actions" page ([`src/app/dashboard/emergency-actions/page.tsx`](src/app/dashboard/emergency-actions/page.tsx:1)) to allow admins with elevated access to manage system-wide lockdown.
    *   Created the "System Configuration" page ([`src/app/dashboard/system-configuration/page.tsx`](src/app/dashboard/system-configuration/page.tsx:1)) to allow admins with elevated access to manage maintenance mode.
    *   Resolved all TypeScript errors in the new pages by adding correct types for API responses and using `useCallback` where necessary.

### 2. System-Wide Audit Logging (Previously Completed)
    *   **Backend ([`../backend/app.py`](../backend/app.py:1)):**
        *   Implemented a new `AuditLog` SQLAlchemy model.
        *   Added a `log_system_event` helper function.
        *   Integrated logging calls into numerous authentication, user management, security key, and system-level API endpoints.
        *   Created a new API endpoint `/api/system-audit-logs` for fetching these logs with filtering and pagination.
        *   Database migrations were successfully generated and applied.
    *   **Frontend ([`src/app/dashboard/audit-logs/page.tsx`](src/app/dashboard/audit-logs/page.tsx:1) & [`src/components/data-table/audit-log-columns.tsx`](src/components/data-table/audit-log-columns.tsx:1)):**
        *   Updated the `AuditLog` type and table column definitions to reflect the new comprehensive log structure.
        *   Modified the audit logs page to fetch data from the new `/api/system-audit-logs` endpoint.
        *   Enhanced filtering options, including a broader set of `actionOptions` and updated global search functionality.
        *   Implemented pagination for the system audit logs table.
        *   Updated generic `DataTable` component ([`src/components/data-table/data-table.tsx`](src/components/data-table/data-table.tsx:1)) to support server-side pagination via `pageCount` prop and `manualPagination: true`.
        *   Standardized loading state display (spinner and text) for Audit Logs ([`src/app/dashboard/audit-logs/page.tsx`](src/app/dashboard/audit-logs/page.tsx:1)), Security Alerts ([`src/app/dashboard/security/page.tsx`](src/app/dashboard/security/page.tsx:1)), and Security Keys ([`src/app/dashboard/security-keys/page.tsx`](src/app/dashboard/security-keys/page.tsx:1)) pages.

1.  **Security Key Management (Backend)**
    *   In [`../backend/app.py`](../backend/app.py:1), the [`reassign_security_key`](../backend/app.py:1497) function was updated to prevent reassigning a security key to a user who already has an active security key. An error `{'error': 'New user already has an active security key. Cannot reassign.'}` with HTTP status 400 is returned.

2.  **User Details Page (Frontend)**
    *   In [`src/app/dashboard/users/[id]/page.tsx`](src/app/dashboard/users/[id]/page.tsx:1), the `handleReassignKey` function was updated to display a specific toast notification ("Failed to reassign key: The selected user already has an active security key.") if the backend returns the corresponding error.

3.  **Theming and Global Styles ([`src/app/globals.css`](src/app/globals.css:1))**
    *   **Sidebar Background:**
        *   Light mode: `--sidebar-bg-light` changed to `#F5F5F1`.
        *   Dark mode: `--sidebar-bg-dark` changed to `#1c1819`.
    *   **Dashboard Overview Card Gradient:**
        *   Removed old `--card-gradient-start` and `--card-gradient-end` variables.
        *   Added new variables for a "to top" gradient:
            *   `--overview-card-gradient-from-light: color-mix(in oklab, var(--primary) 10%, transparent);`
            *   `--overview-card-gradient-to-light: color-mix(in oklab, var(--primary) 2%, transparent);`
            *   `--overview-card-gradient-from-dark: color-mix(in oklab, var(--primary) 15%, var(--card));`
            *   `--overview-card-gradient-to-dark: var(--card);`
            *   General purpose `--overview-card-gradient-from` and `--overview-card-gradient-to` are set based on the current theme.
    *   **Card Borders:**
        *   Added new CSS variables to use sidebar background colors for card borders.
            *   `--card-border-light: var(--sidebar-bg-light);`
            *   `--card-border-dark: #252521;` /* Final dark mode card border */
            *   `--card-border-themed` (points to the theme-specific variable).
    *   **Input Borders:**
        *   Dark mode input border (`--border`) reverted to `#46442f`.

4.  **Dashboard Layout ([`src/app/dashboard/layout.tsx`](src/app/dashboard/layout.tsx:1))**
    *   Search Input: The `Input` component for search now has a `rounded-xl` class.
    *   Sidebar Trigger: The `SidebarTrigger` button now has `rounded-full` and `bg-sidebar` classes, with `border-sidebar-border`.

5.  **Sidebar Component ([`src/components/ui/sidebar.tsx`](src/components/ui/sidebar.tsx:1))**
    *   Active Menu Item: The `sidebarMenuButtonVariants` were updated. Active items (`data-[active=true]`) now have `rounded-full`. Non-active items retain `rounded-xl`.

6.  **Card Component ([`src/components/ui/card.tsx`](src/components/ui/card.tsx:1))**
    *   Border Styling: Updated to use explicit classes `border border-solid border-[var(--card-border-themed)]` to ensure correct application of themed border color.
    *   Border Radius: Changed from `rounded-xl` to `rounded-2xl`.

7.  **Dashboard Overview Page ([`src/app/dashboard/page.tsx`](src/app/dashboard/page.tsx:1))**
    *   **Overview Cards Styling:**
        *   Background: Applied the new "to top" gradient: `bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)]`.
        *   Text Colors: Adjusted for visibility against the new gradient (using `text-foreground` and `text-muted-foreground`).
        *   Icons: Color changed to `text-muted-foreground`.
        *   Progress Bar: Track color changed to `bg-foreground/20` and indicator to `[&>div]:bg-foreground`.
        *   Badge: Colors for "Successful Logins" badge updated for better visibility on the gradient and `bg-transparent` added.
    *   **Pie Chart Borders (Dark Mode):**
        *   Removed white border from "Security Metrics" and "Device Distribution" pie charts by adding `stroke="none"` to the `Pie` components.
        *   Removed `border` class from the custom tooltip content `div` for the "Security Metrics" chart.
    *   **Login Attempts Chart (Refactored with shadcn Chart Components):**
        *   Integrated `ChartContainer`, `ChartTooltip`, `ChartLegend` from `@/components/ui/chart`.
        *   Time range filter now uses `Select` component from `@/components/ui/select`.
        *   Defined `loginAttemptsChartConfig` for labels and colors (successful: `#8B5CF6`, failed: `var(--chart-4)`).
        *   Implemented **stacked** areas with gradient fills (using `stackId="a"`) to match example code.
        *   X-axis and tooltip labels format dates as "Month Day"; XAxis `type` prop removed.
        *   Adjusted `AreaChart` margins to `{ left: 12, right: 12, top: 5, bottom: 5 }`.
        *   Explicit `<YAxis />` component removed (Recharts auto-configures).
        *   Legend displayed at the bottom.
        *   Card description dynamically updates with selected time range.
        *   Ensured `AreaChart` `data` prop uses the fetched `loginAttempts` state.
        *   Corrected tooltip `labelFormatter` to remove `year: "numeric"` to prevent incorrect year display.


8.  **Login Page UI ([`src/app/login/page.tsx`](src/app/login/page.tsx:1))**
    *   The "OR" divider between password login and security key login buttons was updated to `<div class="flex items-center gap-3"><div class="w-full border-t"></div><span class="text-muted-foreground shrink-0 text-sm">or continue with</span><div class="w-full border-t"></div></div>`.
    *   The "Login with Security Key" button background was changed to `bg-input` to match the style of input fields.

9.  **Previously Documented (and still relevant):**
    *   Security key management interface (Security Keys Table & Details pages).
    *   Refined logic for "Register Key" and "Reset Key" actions.
    *   Security Key Audit Log UI and Backend enhancements.
    *   Locked Accounts Management UI and backend logic.
    *   General Theme Implementation (primary color, dark mode background, chart palette, input/button rounding).
    *   Sidebar enhancements for icon-only collapsed state.
    *   User table client-side filtering.
    *   Chat Page HID FIDO Security Key integration for dynamic model availability.

## Recent Decisions
1.  **Secure Admin Context**: Implemented a session-based `authentication_level` to differentiate between password-only and security key-based logins. This is used to control access to high-privilege UI and API endpoints.
2.  **State Persistence**: Adopted Zustand's `persist` middleware to ensure the authentication state (including the new `authenticationLevel`) survives page reloads, fixing a critical race condition.
3.  **Key Reassignment Security:** Implemented backend check to prevent reassigning a key to a user who already has an active one. Frontend toast notification added for this specific error.
4.  **Dashboard Styling:**
    *   Sidebar background colors updated for both light (`#F5F5F1`) and dark (`#1c1819`) modes.
    *   Dashboard search input and sidebar trigger button styling refined (border radius, background).
    *   Active sidebar menu items now have a `rounded-full` border radius.
    *   Overview cards on the dashboard now use a "to top" gradient based on the primary theme color. Card border color in dark mode is now `#252521`. Card component styling updated for explicit border application. Card border radius increased to `rounded-2xl`. Text colors adjusted for visibility.
    *   Removed white borders from pie charts in dark mode.
    *   Login Attempts chart refactored to use shadcn `ChartContainer` and `Select` for filters, with styling and functionality aligned with the provided interactive example.
3.  **Login Page UI:** The "OR" divider on the login page was updated for clarity and modern styling. The "Login with Security Key" button background was also updated to match input fields.
4.  **Theming Variables:** Introduced new CSS variables in `globals.css` for card gradients. Card border color for dark mode set to `#252521`. Input border color for dark mode reverted to `#46442f`.

## Active Technical Patterns
1.  **Data Table Pattern:** Consistent use for displaying security-related information, with features like filtering, pagination, and standardized action handling.
2.  **Security Patterns:** WebAuthn, locked account management, audit logging, refined key reassignment logic, and the new session-based Secure Admin Context.
3.  **State Management**: Zustand with `persist` middleware for robust, persistent global state.
4.  **Layout Patterns:** Dashboard layout with a collapsible, theme-aware sidebar.
4.  **Notification Pattern:** Standardized use of `sonner` for toast notifications.
5.  **Theming Pattern:** `next-themes` for theme management, extensive use of CSS custom properties for theme-specific styling (colors, gradients, borders, radii).

## Current Considerations
1.  **UI/UX:**
    *   Ensuring the new card gradients and border colors look good and are accessible in both themes.
    *   Verifying text visibility and contrast across all themed components.
    *   Confirming the increased card border radius (`rounded-2xl`) is visually appealing.
2.  **Backend Logic:** Confirming the security key reassignment logic correctly handles all edge cases.
3.  **CSS Specificity:** Ensuring Tailwind JIT compiler correctly interprets and applies styles using CSS variables, especially for gradients and borders.