# Progress Tracking: Argus AI Secure

## Implemented Features

### Authentication
- [x] Login page implementation
    - [x] Updated "OR" divider styling on login page ([`src/app/login/page.tsx`](src/app/login/page.tsx:1)).
    - [x] Updated "Login with Security Key" button background to match input fields ([`src/app/login/page.tsx`](src/app/login/page.tsx:1)).
- [x] Signup page implementation
- [x] WebAuthn integration
- [x] Authentication flows
- [x] Backend account locking logic updated (manual admin unlock, locks at 5 attempts, `failed_login_attempts` are now reset to 0 upon admin unlock, `unlocked_by` stores admin username, added check for admin's username before unlock, migration script corrected)
- [x] **Backend Key Reassignment Logic:** Updated [`reassign_security_key`](../backend/app.py:1497) in [`../backend/app.py`](../backend/app.py:1) to prevent reassignment to a user already possessing an active key.
- [x] **Frontend Key Reassignment Toast:** Added specific toast notification in [`src/app/dashboard/users/[id]/page.tsx`](src/app/dashboard/users/[id]/page.tsx:1) for the "user already has an active key" error.

### Dashboard
- [x] Main dashboard layout
    - [x] **Search Input Styling:** In [`src/app/dashboard/layout.tsx`](src/app/dashboard/layout.tsx:1), search input border radius changed to `rounded-xl`.
    - [x] **Sidebar Trigger Styling:** In [`src/app/dashboard/layout.tsx`](src/app/dashboard/layout.tsx:1), sidebar trigger button border radius changed to `rounded-full` and background set to `bg-sidebar`.
- [x] Sidebar navigation (**"Security Keys" and "Audit Logs" are now top-level menu items. "Security" remains a top-level item linking to [`/dashboard/security`](/dashboard/security).**)
    - [x] **Active Menu Item Styling:** In [`src/components/ui/sidebar.tsx`](src/components/ui/sidebar.tsx:1), active `SidebarMenuButton` now has `rounded-full` border radius.
- [x] Security overview page
    - [x] **Overview Cards Styling ([`src/app/dashboard/page.tsx`](src/app/dashboard/page.tsx:1)):**
        - Applied a "to top" gradient background using new CSS variables (`--overview-card-gradient-from`, `--overview-card-gradient-to`) defined in [`src/app/globals.css`](src/app/globals.css) with `color-mix`.
        - Adjusted text colors for visibility (`text-foreground`, `text-muted-foreground`).
        - Updated Progress bar and Badge colors for theme consistency.
    - [x] **Pie Chart Borders (Dark Mode) ([`src/app/dashboard/page.tsx`](src/app/dashboard/page.tsx:1)):** Removed white borders by adding `stroke="none"` to `Pie` components and removing border from custom tooltip.
- [x] **New:** Security Keys page ([`src/app/dashboard/security-keys/page.tsx`](src/app/dashboard/security-keys/page.tsx:1)) with data table for managing security keys. **Now fetches data from backend, includes global search ("Search...") and status filter (button text: "All Statuses", "Active", "Inactive").**
- [x] Locked accounts view (**UI refined: single search filter with increased width (`max-w-md`), styling aligned with other tables, sonner toasts for notifications, "Action" column header, standardized button style, "Unlock Account" button now has a confirmation dialog styled with `font-montserrat`, "Successful Attempts" column removed**)
- [x] Users management (**Enhanced with client-side search and dropdown filters for role & security key status. Filters are part of the `DataTable` via a `toolbar` prop. Filter controls use `font-montserrat`. Security key filter labels updated.**)
- [x] Audit logs view
    - [x] **UI Fix:** Action badges in Security Key Audit Logs table ([`src/components/data-table/audit-log-columns.tsx`](src/components/data-table/audit-log-columns.tsx:1)) now have transparent backgrounds and theme-aware text/border colors for improved dark mode visibility.
- [x] Settings page

### UI Components
- [x] **Card Component ([`src/components/ui/card.tsx`](src/components/ui/card.tsx:1)):**
    - Border styling updated to use explicit `border border-solid border-[var(--card-border-themed)]` for robust color application.
    - Border radius increased to `rounded-2xl`.

### Security Features
- [x] Security key management
    - [x] **New:** Created Security Keys table ([`src/app/dashboard/security-keys/page.tsx`](src/app/dashboard/security-keys/page.tsx:1)) with columns: User, Model, Type, Serial Number, Status, Registered On, Last Used, Action. ([`src/components/data-table/security-keys-columns.tsx`](src/components/data-table/security-keys-columns.tsx:1), [`src/components/data-table/security-keys-data-table.tsx`](src/components/data-table/security-keys-data-table.tsx:1)). **Table now fetches from `/api/security-keys/all`, has global search ("Search...") and status filter (button text: "All Statuses", "Active", "Inactive"). Status badges styled. Action column dropdown updated to match user details page style: "Edit Details" (with icon and modal using Select components for Model/Type, TS errors fixed), "View Details" (with icon), "Delete" (with icon and confirmation). Separator removed.**
    - [x] **New:** Created Security Key Details page ([`src/app/dashboard/security-keys/[id]/page.tsx`](src/app/dashboard/security-keys/[id]/page.tsx:1)) to display individual key information (Credential ID and Sign Count removed) and its audit logs (title changed to "Security Key History", uses `AuditDataTable` for filtering (placeholder "Search...", `onChange` handler in `AuditDataTable` now correctly sets filter only on `performedBy` column, which has a custom `filterFn` to check both `performedBy.username` and `action`), "User" column removed from audit logs), fetched from `/api/security-keys/<id>`. Status badge styling for "inactive" corrected. Syntax error in AuditDataTable component usage fixed. "Registered On" and "Deactivated On" now display time below the date (time text color changed to `text-foreground`).
    - [x] **Refined UI logic in [`src/components/data-table/security-key-columns.tsx`](src/components/data-table/security-key-columns.tsx:1) for security key deactivation/reset/re-registration flow. "Register Key" and "Reset Key" options in the dropdown menu are now conditionally rendered (shown/hidden) based on the key's `isActive`, `deactivatedAt`, and `credentialId` status to guide admins by only showing the currently relevant action.**
        - If `!isActive && deactivatedAt !== null && credentialId !== null` (deactivated, needs reset): Show "Reset Key", hide "Register Key".
        - If `!isActive && (deactivatedAt === null || credentialId === null)` (reset or never formally deactivated): Show "Register Key", hide "Reset Key".
    - [x] **Verified backend logic in [`../backend/app.py`](../backend/app.py:1) (`reset_security_key` and `webauthn_register_complete`) supports this flow by correctly nullifying `credentialId` on reset and updating the existing key record on re-registration when `forceRegistration` and `keyId` are provided.**
- [x] Locked accounts monitoring (**Improved data table UI: single search with `max-w-md`, "Action" column, standardized button style, unlock confirmation modal with consistent styling, "Successful Attempts" column removed**)
- [x] Audit logging system
    - [x] **Backend ([`../backend/app.py`](../backend/app.py:1)):**
        - **Added new endpoint `/api/security-keys/all` to fetch all security keys for the main table.**
        - **Added new endpoint `/api/security-keys/<int:key_id>` to fetch details for a single security key, including its audit logs.**
        - Ensured `SecurityKeyAudit` logs are created for `re-register` actions within the `webauthn_register_complete` function.
        - **Revised logic in `webauthn_register_complete` to more reliably determine `actor_id` for the `performed_by` field in `SecurityKeyAudit`. It defaults to `user.id` (for self-registration) and updates to the admin's ID if a valid `auth_token` corresponding to an admin user is provided.**
- [x] User activity tracking

### AI Integration
- [x] AI chat implementation ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1))
- [x] AI providers setup
- [x] AI tools integration
- [x] Dynamic AI Model Availability via USB Detection:
    - Implemented a local Python helper application ([`../backend/usb_detector.py`](../backend/usb_detector.py:1)) using WebSockets to detect both "normal" (non-WebAuthn) USB device connections and HID FIDO security key connect/disconnect events. **The `vendorId` and `productId` in the WebSocket messages sent to the frontend, as well as in the payload sent to the Flask backend for HID events, now use 4-digit hexadecimal string representations (e.g., "1050", "0407") for consistency.**
    - Frontend chat page ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) connects to this helper and adjusts available AI models for email/password authenticated users based on USB status.
    - Users logged in via WebAuthn security keys retain full model access irrespective of normal USB status (though physical presence of the key, now detected via HID, is also a factor for model availability).
    - Resolved Python `websockets` library v15.0.1 API incompatibilities.
    - [x] **HID FIDO Security Key Detection: `usb_detector.py` now continuously monitors for HID FIDO keys, sending connect/disconnect events to the frontend. The chat page ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) uses this to adjust model availability in real-time, leveraging a consolidated `hidKey` state object (where `vendorId` and `productId` are stored as hex strings) and `useRef` for robust state access in WebSocket handlers. Toast notifications for these events now display the VID/PID in hexadecimal format.**
    - [x] **Chat Page ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)): Modified WebSocket `onclose` handler to always attempt reconnection if the user is logged in and the connection was not closed cleanly. This restores the behavior where the UI can detect the helper app even if it's started after the page loads. The `onerror` handler still logs a `console.warn` once to prevent initial error toast/overlay spam but no longer halts subsequent `onclose`-triggered reconnection attempts.**

### UI/UX Enhancements
- [x] Implemented Dark/Light Theme:
    - Added `next-themes` for theme management.
    - Created `ThemeProvider` (with corrected `ThemeProviderProps` import) and `ThemeToggleButton` components.
    - Defined CSS variables in `globals.css` for light/dark modes, new primary color `#2563eb` (blue), dark background `#0b0a0a`, and a regenerated blue-based chart color palette.
        - **Sidebar Background:** Light: `#F5F5F1`, Dark: `#1c1819`.
        - **Card Gradient:** New variables `--overview-card-gradient-from` and `--overview-card-gradient-to` using `color-mix` for a "to top" gradient.
        - **Card Border:** New variables `--card-border-themed` defined. Dark mode card border (`--card-border-dark`) set to `#252521`.
        - **Input Border:** Dark mode input border (`--border`) reverted to `#46442f`.
    - Integrated theme toggle into the main header (`src/components/header.tsx`) and dashboard layout (`src/app/dashboard/layout.tsx`) for universal visibility.
- [x] Styling Consistency & Fixes:
    - Applied `rounded-xl` to most `Button` and `Input` components globally (except dashboard search input).
    - Updated `Textarea` component wrapper to `rounded-xl`.
    - Chat textarea submit button (`src/components/textarea.tsx`) now uses the new primary blue color background and foreground text.
    - User-sent chat messages (`src/components/message.tsx`) now have the new primary blue color background and foreground text.
    - "Login with Security Key" button (`src/app/login/page.tsx`) now has the new primary blue color border.
    - Ensured buttons on Users, Locked Accounts, Security, and User Details dashboard pages use the default primary blue styling (action buttons) or blue outline styling ("Cancel" buttons) by removing/adjusting explicit classes and variants, and updated backgrounds to be theme-aware.
    - [x] User Details Page Modals: Ensured important instructional text within Register/Reset/Reassign Key modals is visible in dark mode (theme-aware text/border, transparent background in dark mode for instructional containers) in `src/app/dashboard/users/[id]/page.tsx`.
- [x] Data Table Enhancements:
    - Loading spinners in Users and Locked Accounts tables are now blue.
    - Removed duplicate pagination controls from the Security page.
    - [x] Users Table: Fixed dark mode visibility for "role", "loginAttempts", "failedAttempts", and "securityKeyStatus" badges in `src/components/data-table/columns.tsx`.
    - [x] User Details Security Keys Table: Fixed dark mode visibility for "Status" badge in `src/components/data-table/security-key-columns.tsx`. **Dropdown action logic updated for deactivation/reset/re-registration flow with conditional rendering.**
- [x] Dashboard Sidebar Enhancement:
    - Updated `src/components/app-sidebar.tsx` to use `collapsible="icon"` mode.
    - Sidebar now collapses to show only icons, with text labels hidden (using conditional rendering and opacity/width classes for robustness).
    - Tooltips display item names on hover when collapsed.
    - Added specific classes to `SidebarMenuButton` and its child `<a>` tag in `app-sidebar.tsx` to improve icon centering in collapsed view.
    - Updated `SidebarMenuButton` in `src/components/ui/sidebar.tsx` to use `bg-primary`, `text-primary-foreground`, and `rounded-full` (was `rounded-xl`) for active links.
- [x] Dashboard Chart Theming:
    - Updated "Login Attempts" chart in `src/app/dashboard/page.tsx` (Refactored to use shadcn Chart Components):
        - Integrated `ChartContainer`, `ChartTooltip`, `ChartLegend` from `@/components/ui/chart`.
        - Time range filter now uses `Select` component from `@/components/ui/select`.
        - Defined `loginAttemptsChartConfig` for labels and colors (successful: `#8B5CF6`, failed: `var(--chart-4)`).
        - Implemented **stacked** areas with gradient fills (using `stackId="a"`) to match example code.
        - X-axis and tooltip labels format dates as "Month Day"; XAxis `type` prop removed.
        - Adjusted `AreaChart` margins to `{ left: 12, right: 12, top: 5, bottom: 5 }`.
        - Explicit `<YAxis />` component removed (Recharts auto-configures).
        - Legend displayed at the bottom.
        - Card description dynamically updates with selected time range.
        - Ensured `AreaChart` `data` prop uses the fetched `loginAttempts` state.
        - Corrected tooltip `labelFormatter` to remove `year: "numeric"` to prevent incorrect year display.
    - Moved the custom legend (displaying "Low Risk", "Medium Risk", "High Risk") from the "Top Locations" chart to be under the "Risk Score Trend" chart in `src/app/dashboard/page.tsx`, and ensured it is correctly positioned within the `CardContent`.
    - Added a new custom legend for the "Top Locations" chart in `src/app/dashboard/page.tsx` to display "Low Severity (<= 5 attempts)", "Medium Severity (<= 15 attempts)", and "High Severity (> 15 attempts)" with corresponding colors, positioned correctly within its `CardContent`.
    - Corrected a malformed JSX comment block in `src/app/dashboard/page.tsx`.
    - Resolved linter errors on line 839 of `src/app/dashboard/page.tsx` by wrapping the `>` character in a JSX expression `{'>'}`.

## In Progress
1.  Security Dashboard Enhancements
    *   Data visualization improvements
    *   Real-time updates
    *   Enhanced filtering (User table now has specific filters. Review if other tables need similar specific filters or if global search is sufficient).
    *   [x] Generic `DataTable` component now supports a `toolbar` prop for custom filter controls.
    *   [x] Generic `DataTable` component now includes pagination.

2.  Locked Accounts Management
    *   Bulk actions implementation
    *   Review recovery workflow based on manual admin unlock with confirmation.

3.  AI Features
    *   Enhanced security insights
    *   Automated threat detection
    *   Security recommendations
    *   [x] Refined USB device detection in `usb_detector.py` to distinguish generic USBs and HID FIDO WebAuthn keys using HID usage pages and VID/PID fallbacks. Frontend logic handles model availability based on these distinct events.
    *   [ ] Consider packaging or auto-start mechanism for the `usb_detector.py` helper application for better UX.

## Known Issues
1.  Performance
    *   Large data table optimization needed
    *   Initial load time optimization

2.  Security
    *   Rate limiting implementation needed
    *   Additional security headers

3.  UX Improvements
    *   Mobile responsiveness refinements
    *   Loading state improvements (standardized spinner, loading state for dialog buttons)
    *   Error handling enhancements (standardized sonner toasts)
    *   Ensure consistent search/filter patterns and input sizing across all data tables (User table filters implemented via `toolbar` prop).
    *   Ensure consistent use of confirmation dialogs (styling and behavior) for critical actions across the application.
    *   [x] Verify new dark/light theme consistency across all components and pages (Initial fixes applied based on feedback).
    *   [ ] Test chart color palette usability in both themes.
    *   Review all data tables for column relevance.
    *   User experience for the local Python USB helper application (e.g., clear instructions if it's not running, connection status indication).
    *   [x] Chat Page: WebSocket `onclose` handler now always attempts reconnection if the user is logged in and the connection was not closed cleanly, restoring detection of the helper app if started after page load. The `onerror` handler still logs a `console.warn` once to prevent initial error toast/overlay spam.

## Next Steps
1.  Short Term
    *   Optimize data table performance
    *   Enhance mobile responsiveness
    *   Implement rate limiting
    *   Review and standardize search/filter UX and input sizing across all data tables (User table is a good example with `toolbar` prop).
    *   [x] Add pagination to all relevant data tables (Generic `DataTable` now has pagination).
    *   Review other critical actions for potential confirmation dialogs and consistent styling.
    *   Review column selection in all data tables for relevance.

2.  Medium Term
    *   Add advanced security analytics
    *   Enhance AI security features
    *   Implement bulk operations for locked accounts

3.  Long Term
    *   Advanced threat detection
    *   Machine learning integration
    *   Automated security response