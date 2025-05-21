# Active Context: Argus AI Secure

## Current Focus
Based on open files and recent activity, development is focused on security management features and user table enhancements:

1.  Security Dashboard Implementation
    *   Security key management interface
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
*   Button color `#e60053` (primary) for both themes.
    *   Textarea submit button in `src/components/textarea.tsx` now uses primary color.
    *   "Login with Security Key" button in `src/app/login/page.tsx` now has primary color border.
*   Dark theme background color `#0b0a0a`.
*   Color palette generated from `#e60053` for charts.
*   Inputs and buttons styled with `rounded-xl` (except chat textarea's internal submit button, which is `rounded-full`).
*   User chat messages in `src/components/message.tsx` now have primary background and foreground text color.

6.  Sidebar Enhancement
    *   Updated `src/components/app-sidebar.tsx` to support an icon-only collapsed state.
        *   Uses `collapsible="icon"` prop from `src/components/ui/sidebar.tsx`.
        *   Text labels are hidden when collapsed using conditional rendering and opacity/width classes.
        *   Tooltips display item titles on hover when collapsed.
        *   Attempted to ensure icon centering in collapsed state by adjusting classes on `SidebarMenuButton` and its child `<a>` tag.

7.  Active Components
*   `src/app/dashboard/users/page.tsx`: User management page. (**Added client-side search and dropdown filters for role and security key status. Filter controls are passed to the `DataTable` via a `toolbar` prop. Applied `font-montserrat` to filter controls. Updated security key filter labels.**)
    *   `src/components/data-table/data-table.tsx`: Generic data table component. (**Added an optional `toolbar` prop to render custom controls like filters. Implemented pagination with "Previous" and "Next" buttons.**)
    *   `locked-accounts-data-table.tsx`: Main interface for locked accounts (**Refined styling, single search filter with `max-w-md`, and notification handling. "Successful Attempts" column removed from display logic.**)
    *   `locked-accounts-columns.tsx`: Data structure for locked accounts (**Updated action column header to "Action", button styling matches "Add User" button, "Unlock Account" button now triggers a confirmation dialog with `font-montserrat` and `sm:max-w-[425px]` styling, "Successful Attempts" column definition removed, uses sonner toasts for actions**)
    *   `security/page.tsx`: Security dashboard implementation
    *   `src/components/app-sidebar.tsx`: Navigation and layout structure. (**Updated to support icon-only collapsed state with tooltips, with specific class adjustments for icon centering and text hiding.**)
    *   `../backend/app.py`: Backend logic for authentication and account management (**Simplified account lock mechanism, removed time-based auto-unlock. `failed_login_attempts` now persist after unlock and increment even if the account is already locked. `unlocked_by` column stores admin username.**)
    *   `src/components/theme-provider.tsx`: New component for `next-themes` integration. (**Corrected `ThemeProviderProps` import path.**)
    *   `src/components/theme-toggle-button.tsx`: New component for theme switching.
    *   `src/app/layout.tsx`: Updated to include `ThemeProvider`.
    *   `src/app/globals.css`: Updated with CSS variables for light/dark themes, primary color `#e60053`, dark background `#0b0a0a`, and chart color palette.
    *   `src/components/ui/button.tsx`: Default `rounded-md` changed to `rounded-xl`.
    *   `src/components/ui/input.tsx`: Default `rounded-md` changed to `rounded-xl`.
    *   `src/components/textarea.tsx`: Textarea wrapper `rounded-2xl` changed to `rounded-xl`. (**Submit button styled with primary color.**)
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
11. Backend: `failed_login_attempts` are no longer reset when an admin unlocks an account.
12. Backend: The `unlocked_by` column in the `Users` table now stores the admin's username (string) instead of their ID (integer), and the foreign key constraint was removed. Database migration required.
13. Backend: `failed_login_attempts` now increment for every incorrect password entry, even if the account is already locked, ensuring the admin sees the total number of attempts. Account locks at 5 failed attempts.
14. User Table Filters: Added search input, role dropdown, and security key status dropdown to the user management page (`src/app/dashboard/users/page.tsx`). These filters are rendered within the `DataTable` component using a new `toolbar` prop.
15. DataTable Component Enhancement: The generic `DataTable` component (`src/components/data-table/data-table.tsx`) was updated to accept a `toolbar` prop for rendering custom controls and to include pagination functionality.
16. Styling Consistency: Applied `font-montserrat` to the user table filter controls for consistency. Updated security key filter labels for clarity.
17. Implemented dark/light theme using `next-themes`.
18. Defined CSS variables in `globals.css` for theming, including primary color `#e60053`, dark theme background `#0b0a0a`, and a chart color palette derived from the primary color.
19. Created a `ThemeToggleButton` component for users to switch themes.
20. Integrated the `ThemeToggleButton` into the main `Header` component and `src/app/dashboard/layout.tsx`.
21. Standardized most button and input elements to use `rounded-xl` styling, with an exception for the chat page's textarea internal button (which is `rounded-full`).
22. Corrected `ThemeProviderProps` import in `src/components/theme-provider.tsx`.
23. Styled the chat textarea's submit button with the primary color (`#e60053`).
24. Styled user-sent chat messages with a primary color background and white text.
25. Styled the "Login with Security Key" button on the login page with a primary color border.
26. Ensured theme toggle button is visible in the admin dashboard by adding it to `src/app/dashboard/layout.tsx`.
27. Enhanced `src/components/app-sidebar.tsx` to provide a collapsible icon-only view with tooltips, similar to the shadcn/ui dashboard example, including attempts to refine icon centering and text hiding in collapsed mode.

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
    *   Locked account management (manual admin unlock with confirmation, `failed_login_attempts` persist and continue to increment post-lock, `unlocked_by` stores admin username).
    *   Audit logging.

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
    *   CSS custom properties (variables) defined in `globals.css` for theme-specific styling (e.g., `--background`, `--foreground`, `--primary`, chart colors).
    *   A dedicated `ThemeProvider` component wraps the application layout.
    *   A `ThemeToggleButton` component allows users to switch themes, integrated into headers.
    *   Consistent corner rounding (`rounded-xl`) applied to UI elements like buttons and inputs for a unified look.
    *   Specific UI elements (chat messages, login buttons) styled with the primary theme color.

## Current Considerations
1.  Security Features
    *   Account locking mechanisms (manual admin unlock with confirmation, locks at 5 attempts, `failed_login_attempts` persist through unlock and increment even if account is already locked, `unlocked_by` stores admin username).
    *   Security key management.
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