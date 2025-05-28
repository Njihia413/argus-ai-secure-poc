# Active Context: Argus AI Secure

## Current Focus
Based on open files and recent activity, development is focused on security management features and user table enhancements:

1.  Security Dashboard Implementation
    *   Security key management interface
        *   **New Feature: Security Keys Table page ([`src/app/dashboard/security-keys/page.tsx`](src/app/dashboard/security-keys/page.tsx:1)) added. Fetches data from new backend endpoint `/api/security-keys/all`. Displays security key details (User, Model, Type, Serial Number, Status, Registered On, Last Used, Action) with a dedicated data table ([`src/components/data-table/security-keys-data-table.tsx`](src/components/data-table/security-keys-data-table.tsx:1)) and column definitions ([`src/components/data-table/security-keys-columns.tsx`](src/components/data-table/security-keys-columns.tsx:1)). Includes global search ("Search...") and status filter (button text: "All Statuses", "Active", "Inactive"). Status badges styled like user details page. Action column dropdown updated to match user details page style: "Edit Details" (with icon and modal using Select components for Model/Type), "View Details" (with icon), "Delete" (with icon and confirmation). Separator removed.**
        *   **New Feature: Security Key Details page ([`src/app/dashboard/security-keys/[id]/page.tsx`](src/app/dashboard/security-keys/[id]/page.tsx:1)) created. Fetches and displays individual security key information (Credential ID and Sign Count removed). Audit log table title changed to "Security Key History", uses `AuditDataTable` for filtering, and "User" column removed from audit logs. Status badge styling for "inactive" corrected.**
        *   Refined logic for "Register Key" and "Reset Key" actions in the security keys table dropdown ([`src/components/data-table/security-key-columns.tsx`](src/components/data-table/security-key-columns.tsx:1)).
            *   If a key is inactive (`!key.isActive`):
                *   If `key.deactivatedAt !== null && key.credentialId !== null` (key is deactivated and needs reset):
                    *   "Reset Key" option is **shown**.
                    *   "Register Key" option is **hidden**.
                *   Else (if `key.deactivatedAt === null || key.credentialId === null`, meaning key is reset or was never formally deactivated):
                    *   "Register Key" option is **shown**.
                    *   "Reset Key" option is **hidden**.
        *   Security Key Audit Log UI: Updated action badges in [`src/components/data-table/audit-log-columns.tsx`](src/components/data-table/audit-log-columns.tsx:1) to have transparent backgrounds and theme-aware text/border colors for better dark mode visibility. Added `initial-register` and `re-register` cases to the badge styling switch.
        *   **Security Key Audit Log Backend ([`../backend/app.py`](../backend/app.py:1)):**
            *   Modified `webauthn_register_complete` to correctly log `re-register` actions in `SecurityKeyAudit`.
            *   **Revised logic in `webauthn_register_complete` to more reliably determine the `actor_id` (who performed the action). It defaults to `user.id` (for self-registration) and updates to the admin's ID if a valid `auth_token` corresponding to an admin user is provided. This `actor_id` is used for the `performed_by` field in audit logs.**
        *   **Backend ([`../backend/app.py`](../backend/app.py:1)): Added new endpoint `/api/security-keys/all` to fetch all security keys. Added `/api/security-keys/<int:key_id>` to fetch single key details including audit logs.**
    *   Dashboard security overview
    *   Integration with WebAuthn

2.  Locked Accounts Management
    *   Data table implementation for locked accounts (**Updated styling, single global search filter with increased width, action button styling with confirmation modal using `font-montserrat`, and removed "Successful Attempts" column**)
    *   Account status monitoring
    *   Account recovery workflows (**Simplified backend logic for account lock, frontend notifications use sonner toasts, unlock action now has a confirmation dialog**)

4.  Theme Implementation
*   Dark theme implementation with light/dark mode toggle.
    *   Fixed `ThemeProviderProps` import in `src/components/theme-provider.tsx`.
    *   Theme toggle button added to `src/app/dashboard/layout.tsx` for visibility.
*   Primary color changed to `#2563eb` (blue) for both themes.
    *   Textarea submit button in `src/components/textarea.tsx` now uses this new primary blue color.
    *   "Login with Security Key" button in `src/app/login/page.tsx` now has this new primary blue color border.
*   Dark theme background color `#0b0a0a` (remains unchanged).
*   Chart color palette regenerated based on the new primary blue color (`#2563eb`) providing distinct variations. "Login Attempts" chart uses `--chart-2` and `--chart-4` from this new blue palette.
*   Inputs and buttons styled with `rounded-xl` (except chat textarea's internal submit button, which is `rounded-full`).
*   User chat messages in `src/components/message.tsx` now have primary background and foreground text color.

6.  Sidebar Enhancement
    *   Updated [`src/components/app-sidebar.tsx`](src/components/app-sidebar.tsx:1) to support an icon-only collapsed state.
        *   **"Security Keys" and "Audit Logs" are now top-level menu items. "Security" remains a top-level item linking to [`/dashboard/security`](/dashboard/security).**
        *   Uses `collapsible="icon"` prop from [`src/components/ui/sidebar.tsx`](src/components/ui/sidebar.tsx:1).
        *   Text labels are hidden when collapsed using conditional rendering and opacity/width classes.
        *   Tooltips display item titles on hover when collapsed.
        *   Attempted to ensure icon centering in collapsed state by adjusting classes on `SidebarMenuButton` and its child `<a>` tag.
        *   Active sidebar links are now styled with the primary blue color and `rounded-xl`.

7.  Active Components
*   `src/app/dashboard/users/page.tsx`: User management page. (**Added client-side search and dropdown filters for role and security key status. Filter controls are passed to the `DataTable` via a `toolbar` prop. Applied `font-montserrat` to filter controls. Updated security key filter labels. Loading spinner color changed to primary blue.**)
    *   `src/components/data-table/columns.tsx`: Columns for Users table. (**Fixed dark mode visibility for "role", "failedAttempts", and "securityKeyStatus" badges by removing hardcoded light-theme classes and using theme-aware styling.**)
    *   `src/components/data-table/data-table.tsx`: Generic data table component. (**Added an optional `toolbar` prop to render custom controls like filters. Implemented pagination with "Previous" and "Next" buttons.**)
    *   `src/components/data-table/locked-accounts-data-table.tsx`: Main interface for locked accounts. (**Refined styling, single search filter with `max-w-md`, notification handling. "Successful Attempts" column removed from display logic. Loading spinner color changed to primary blue.**)
    *   `locked-accounts-columns.tsx`: Data structure for locked accounts (**Updated action column header to "Action", button styling matches "Add User" button, "Unlock Account" button now triggers a confirmation dialog with `font-montserrat` and `sm:max-w-[425px]` styling, "Successful Attempts" column definition removed, uses sonner toasts for actions**)
    *   `src/app/dashboard/security/page.tsx`: Security dashboard implementation. (**"Export Report" and pagination buttons updated to default blue styling. Removed duplicate manual pagination controls.**)
    *   [`src/components/app-sidebar.tsx`](src/components/app-sidebar.tsx:1): Navigation and layout structure. (**Updated to support icon-only collapsed state with tooltips. "Security Keys" and "Audit Logs" are now top-level menu items. "Security" remains a top-level item linking to [`/dashboard/security`](/dashboard/security).**)
    *   [`src/components/ui/sidebar.tsx`](src/components/ui/sidebar.tsx:1): Base sidebar UI component. (**Updated `SidebarMenuButton` active state to use `bg-primary`, `text-primary-foreground`, and `rounded-xl`.**)
    *   [`src/app/dashboard/page.tsx`](src/app/dashboard/page.tsx:1): Main dashboard page. (**"Login Attempts" chart updated to use theme color palette. Custom legend for "Risk Score Trend" chart now correctly displays "Low Risk", "Medium Risk", "High Risk" labels and is positioned correctly within the `CardContent` under this chart. The custom legend for the "Top Locations" chart has been updated to include attempt counts: "Low Severity (<= 5 attempts)", "Medium Severity (<= 15 attempts)", "High Severity (> 15 attempts)" and is positioned correctly within its `CardContent`. Corrected a malformed JSX comment block. Resolved linter errors on line 839 by wrapping the `>` character in a JSX expression `{'>'}`.**)
    *   **New:** [`src/app/dashboard/security-keys/page.tsx`](src/app/dashboard/security-keys/page.tsx:1): Page for displaying security keys table. **Now fetches data from `/api/security-keys/all`.**
    *   **New:** [`src/components/data-table/security-keys-columns.tsx`](src/components/data-table/security-keys-columns.tsx:1): Column definitions for the security keys table. **Interface updated, status badge styling aligned. Action column header added, dropdown updated to include "Edit Details" (with icon and modal using Select components for Model/Type, consistent with user details page, TS errors fixed), "View Details" (with icon, navigates to details page), and "Delete" (with icon, confirmation dialog, and API call). Separator removed.**
    *   **New:** [`src/components/data-table/security-keys-data-table.tsx`](src/components/data-table/security-keys-data-table.tsx:1): Data table component for security keys. **Added global search ("Search...") across multiple columns and a status dropdown filter (button text updated to show only selected status, e.g., "All Statuses").**
    *   **New:** [`src/app/dashboard/security-keys/[id]/page.tsx`](src/app/dashboard/security-keys/[id]/page.tsx:1): Details page for a single security key. **Displays key information (Credential ID and Sign Count removed). Audit log table title changed to "Security Key History", uses `AuditDataTable` for filtering (placeholder "Search...", `onChange` handler in `AuditDataTable` now correctly sets filter only on `performedBy` column, which has a custom `filterFn` to check both `performedBy.username` and `action`). Status badge styling for "inactive" corrected. Syntax error in AuditDataTable component usage fixed. "Registered On" and "Deactivated On" now display time below the date (time text color changed to `text-foreground`).**
    *   `src/components/data-table/locked-accounts-columns.tsx`: Columns for Locked Accounts table. (**"Unlock Account" & "Confirm Unlock" buttons to default blue; "Cancel" button to blue outline.**)
    *   `src/app/dashboard/users/[id]/page.tsx`: User details page. (**Action buttons to default blue; "Cancel" buttons to blue outline; backgrounds made theme-aware. Corrected text visibility in dark mode for Register/Reset/Reassign Key modal instructions/notes by applying theme-aware text/border colors and ensuring transparent backgrounds in dark mode for instructional containers.**)
    *   `src/components/data-table/security-key-columns.tsx`: Columns for Security Keys table in User Details page. (**Fixed dark mode visibility for "Status" badges. Updated dropdown logic to conditionally render "Register Key" and "Reset Key" based on key status.**)
    *   `src/components/data-table/audit-log-columns.tsx`: Columns for Security Key Audit Logs. (**Updated action badge styling for theme-aware transparent backgrounds. "User" column removed. Added custom `filterFn` to `performedBy` column to enable search by performer or action.**)
    *   [`../backend/app.py`](../backend/app.py:1): Backend logic. (**Added `/api/security-keys/all` and `/api/security-keys/<int:key_id>` endpoints. Updated `webauthn_register_complete` for audit logs.**)
    *   `src/components/theme-provider.tsx`: New component for `next-themes` integration. (**Corrected `ThemeProviderProps` import path.**)
    *   `src/components/theme-toggle-button.tsx`: New component for theme switching.
    *   `src/app/layout.tsx`: Updated to include `ThemeProvider`.
    *   `src/app/globals.css`: Updated CSS variables for `--primary`, `--ring`, and `--chart-*` to reflect the new blue color scheme (`#2563eb`).
    *   `src/components/ui/button.tsx`: Default `rounded-md` changed to `rounded-xl`. (**Outline variant updated for blue border and text.**)
    *   `src/components/ui/input.tsx`: Default `rounded-md` changed to `rounded-xl`.
    *   `src/components/textarea.tsx`: Textarea wrapper `rounded-xl` changed to `rounded-xl`. (**Submit button styled with primary color.**)
    *   `src/components/header.tsx`: Integrated `ThemeToggleButton`.
    *   `src/components/message.tsx`: (**User messages styled with primary background and foreground text.**)
    *   `src/app/login/page.tsx`: (**"Login with Security Key" button border styled with primary color.**)
    *   `src/app/dashboard/layout.tsx`: (**Added `ThemeToggleButton` to dashboard header.**)

## Recent Decisions
1.  Using data tables for security information display.
2.  Implementing WebAuthn for authentication.
3.  Structured routing for security features.
4.  Standardized on `sonner` for toast notifications across frontend components.
5.  Simplified account locking in the backend to require manual admin unlock.
6.  Consolidated multiple search filters in `locked-accounts-data-table.tsx` into a single global search input with increased width (`max-w-md`).
7.  Standardized action button styling in data tables to match the "Add User" button style.
8.  Renamed the actions column header to "Action" for clarity in `locked-accounts-columns.tsx`.
9.  Added a confirmation dialog (`shadcn/ui Dialog`) to the "Unlock Account" button in `locked-accounts-columns.tsx` to prevent accidental unlocks, styled with `font-montserrat` and `sm:max-w-[425px]`.
10. Removed the "Successful Attempts" column from the locked accounts data table as it was deemed redundant.
11. Backend: `failed_login_attempts` are now reset to 0 when an admin unlocks an account.
12. Backend: The `unlocked_by` column in the `Users` table now stores the admin's username (string) instead of their ID (integer), and the foreign key constraint was removed. Database migration required.
13. Backend: `failed_login_attempts` now increment for every incorrect password entry, even if the account is already locked, ensuring the admin sees the total number of attempts. Account locks at 5 failed attempts.
14. User Table Filters: Added search input, role dropdown, and security key status dropdown to the user management page (`src/app/dashboard/users/page.tsx`). These filters are rendered within the `DataTable` component using a new `toolbar` prop.
15. DataTable Component Enhancement: The generic `DataTable` component (`src/components/data-table/data-table.tsx`) was updated to accept a `toolbar` prop for rendering custom controls and to include pagination functionality.
16. Styling Consistency: Applied `font-montserrat` to the user table filter controls for consistency. Updated security key filter labels for clarity.
17. Implemented dark/light theme using `next-themes`.
18. Changed the primary theme color from `#e60053` (pink) to `#2563eb` (blue). Updated CSS variables in `globals.css` for `--primary`, `--ring`, and regenerated the `--chart-*` palette accordingly. Dark theme background (`#0b0a0a`) remains unchanged.
19. Created a `ThemeToggleButton` component for users to switch themes.
20. Integrated the `ThemeToggleButton` into the main `Header` component and `src/app/dashboard/layout.tsx`.
21. Standardized most button and input elements to use `rounded-xl` styling, with an exception for the chat page's textarea internal button (which is `rounded-full`).
22. Corrected `ThemeProviderProps` import in `src/components/theme-provider.tsx`.
23. Styled the chat textarea's submit button with the new primary blue color.
24. Styled user-sent chat messages with the new primary blue color background and white text.
25. Styled the "Login with Security Key" button on the login page with the new primary blue color border.
26. Ensured theme toggle button is visible in the admin dashboard by adding it to `src/app/dashboard/layout.tsx`.
27. Enhanced `src/components/app-sidebar.tsx` to provide a collapsible icon-only view with tooltips, similar to the shadcn/ui dashboard example, including attempts to refine icon centering and text hiding in collapsed mode.
28. Updated "Login Attempts" chart on the dashboard (`src/app/dashboard/page.tsx`) to use more distinct colors from the theme's updated chart palette (`--chart-2` and `--chart-4`) instead of the previous theme colors.
29. Updated active link styling in `src/components/ui/sidebar.tsx` to use the primary blue color and `rounded-xl`.
30. Ensured buttons on Users page (`src/app/dashboard/users/page.tsx`) use default primary blue styling (Add User, Create User, Update User, Cancel buttons in dialogs).
31. Ensured buttons on Locked Accounts page (via `src/components/data-table/locked-accounts-columns.tsx`) use default primary blue styling (Unlock Account, Confirm Unlock, Cancel buttons in dialog).
32. Ensured buttons on Security page (`src/app/dashboard/security/page.tsx`) use default primary blue styling (Export Report, pagination buttons).
33. Updated User Details page (`src/app/dashboard/users/[id]/page.tsx`): Ensured action buttons use primary blue styling, "Cancel" buttons use blue outline, backgrounds are theme-aware. Corrected important instructional text within modals (Register/Reset/Reassign Key) to be visible in dark mode by using theme-aware text/border colors and ensuring transparent backgrounds in dark mode for instructional containers.
34. User Details Security Keys Table: Corrected "Status" badge styling in `src/components/data-table/security-key-columns.tsx` for dark mode visibility. **Further updated dropdown logic to conditionally render "Register Key" and "Reset Key" based on key status (`isActive`, `deactivatedAt`, `credentialId`).**
35. Modified `outline` button variant in `src/components/ui/button.tsx` to use primary blue for border and text, with appropriate hover states.
36. Changed loading spinner color to primary blue on Users page and Locked Accounts data table.
37. Removed duplicate manual pagination controls from the Security page, relying on the DataTable's built-in pagination.
38. Users Table Badge Styling: Corrected badge styling in `src/components/data-table/columns.tsx` for "role", "loginAttempts", "failedAttempts", and "securityKeyStatus" to ensure visibility in dark mode by removing hardcoded light-theme classes and applying theme-aware text/border colors.
39. **Security Key Deactivation/Re-registration Flow: Refined UI logic in [`src/components/data-table/security-key-columns.tsx`](src/components/data-table/security-key-columns.tsx:1) to conditionally render (show/hide) "Register Key" and "Reset Key" options based on the key's `isActive`, `deactivatedAt`, and `credentialId` status. This ensures only the relevant action is presented to the admin. Ensured backend (`../backend/app.py`) already supports this flow via `reset_security_key` (nullifies `credentialId`) and `webauthn_register_complete` (updates existing key record if `forceRegistration` and `keyId` are provided).**
40. **Security Key Audit Log Enhancements:**
    *   **UI:** Updated action badge styling in [`src/components/data-table/audit-log-columns.tsx`](src/components/data-table/audit-log-columns.tsx:1) for theme-aware transparent backgrounds.
    *   **Backend ([`../backend/app.py`](../backend/app.py:1)):** Modified `webauthn_register_complete` to log `re-register` actions and to more reliably determine and use the admin's ID (if available via `auth_token`) or the target user's ID for the `performed_by` audit log field.

## Active Technical Patterns
1.  Data Table Pattern
    *   Reusable table structure with `CardContent` wrappers for consistent styling.
    *   Customizable columns with sorting.
    *   Supports a `toolbar` prop for custom filter controls (e.g., search input, dropdowns) to be rendered above the table.
    *   Includes built-in pagination controls.
    *   Consistent data display and action handling (standardized button styles, confirmation dialogs for critical actions with consistent font and sizing).
    *   Column definitions are carefully selected to display relevant information.

2.  Security Patterns
    *   WebAuthn integration.
    *   Locked account management (manual admin unlock with confirmation, `failed_login_attempts` are reset to 0 upon unlock, `unlocked_by` stores admin username).
    *   Audit logging (**Enhanced for security key re-registrations and more reliable `performed_by` tracking based on `auth_token`**).
    *   **Security Key Lifecycle Management: Admins are guided to reset a deactivated key (which nullifies its `credentialId` on the backend) before it can be re-registered. The UI in the security keys table dropdown now enforces this by showing only the "Reset Key" option if a key is deactivated but not yet reset, and only "Register Key" if it's ready for registration.**

3.  Layout Patterns
    *   Dashboard layout with a collapsible sidebar (icon-only mode with tooltips).
    *   Security-focused navigation.
    *   Responsive design implementation.

4.  Notification Pattern
    *   Using `sonner` for consistent toast notifications for user feedback (e.g., account unlock success/failure).

5.  User Interaction Pattern
    *   Confirmation dialogs for destructive or sensitive actions (e.g., unlocking an account), styled consistently with the application's typography (`font-montserrat`).

6.  Theming Pattern (New)
    *   Utilizes `next-themes` for managing light, dark, and system themes.
    *   CSS custom properties (variables) defined in `globals.css` for theme-specific styling (e.g., `--background`, `--foreground`, new `--primary` blue, and a regenerated blue-based chart color palette).
    *   A dedicated `ThemeProvider` component wraps the application layout.
    *   A `ThemeToggleButton` component allows users to switch themes, integrated into headers.
    *   Consistent corner rounding (`rounded-xl`) applied to UI elements like buttons and inputs for a unified look.
    *   Specific UI elements (chat messages, login buttons, "Cancel" buttons) styled with the primary theme color (solid or outline).

## Current Considerations
1.  Security Features
    *   Account locking mechanisms (manual admin unlock with confirmation, locks at 5 attempts, `failed_login_attempts` are reset to 0 upon admin unlock, `unlocked_by` stores admin username).
    *   Security key management (**Verified deactivation/reset/re-registration flow with conditional rendering of actions. Audit logs for these actions improved for accuracy of `performed_by`.**).
    *   Audit trail implementation.

2.  User Experience
    *   Dashboard information hierarchy.
    *   Security status visibility.
    *   Account recovery flows (admin-initiated unlock with confirmation step).
    *   Consistent notification patterns.
    *   Simplified search/filtering in data tables with appropriate input sizing.
    *   Clear confirmation steps for critical actions, with consistent dialog styling.
    *   Relevance of displayed columns in data tables.
    *   Standardized placement of filter controls within data tables using the `toolbar` prop.
    *   Consistent pagination for data tables.
    *   Theming: Ensuring the new dark/light theme is applied consistently and looks good across all components. Verifying chart color palette usability.

3.  Integration Points
    *   Backend API integration for account management.
    *   AI assistance features.
    *   Authentication flows.
    *   Theming: Ensuring the new dark/light theme is applied consistently and looks good across all components. Verifying chart color palette usability.

3.  Integration Points
    *   Backend API integration for account management.
    *   AI assistance features.
    *   Authentication flows.