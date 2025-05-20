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

3.  Active Components
    *   `src/app/dashboard/users/page.tsx`: User management page. (**Added client-side search and dropdown filters for role and security key status. Filter controls are passed to the `DataTable` via a `toolbar` prop. Applied `font-montserrat` to filter controls. Updated security key filter labels.**)
    *   `src/components/data-table/data-table.tsx`: Generic data table component. (**Added an optional `toolbar` prop to render custom controls like filters. Implemented pagination with "Previous" and "Next" buttons.**)
    *   `locked-accounts-data-table.tsx`: Main interface for locked accounts (**Refined styling, single search filter with `max-w-md`, and notification handling. "Successful Attempts" column removed from display logic.**)
    *   `locked-accounts-columns.tsx`: Data structure for locked accounts (**Updated action column header to "Action", button styling matches "Add User" button, "Unlock Account" button now triggers a confirmation dialog with `font-montserrat` and `sm:max-w-[425px]` styling, "Successful Attempts" column definition removed, uses sonner toasts for actions**)
    *   `security/page.tsx`: Security dashboard implementation
    *   `app-sidebar.tsx`: Navigation and layout structure
    *   `../backend/app.py`: Backend logic for authentication and account management (**Simplified account lock mechanism, removed time-based auto-unlock. `failed_login_attempts` now persist after unlock and increment even if the account is already locked. `unlocked_by` column stores admin username.**)

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
    *   Dashboard layout with sidebar.
    *   Security-focused navigation.
    *   Responsive design implementation.

4.  Notification Pattern
    *   Using `sonner` for consistent toast notifications for user feedback (e.g., account unlock success/failure).

5.  User Interaction Pattern
    *   Confirmation dialogs for destructive or sensitive actions (e.g., unlocking an account), styled consistently with the application's typography (`font-montserrat`).

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

3.  Integration Points
    *   Backend API integration for account management.
    *   AI assistance features.
    *   Authentication flows.