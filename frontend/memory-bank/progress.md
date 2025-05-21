# Progress Tracking: Argus AI Secure

## Implemented Features

### Authentication
- [x] Login page implementation
- [x] Signup page implementation
- [x] WebAuthn integration
- [x] Authentication flows
- [x] Backend account locking logic simplified (manual admin unlock, locks at 5 attempts, `failed_login_attempts` persist through unlock and increment even if account is already locked, `unlocked_by` stores admin username, migration script corrected)

### Dashboard
- [x] Main dashboard layout
- [x] Sidebar navigation
- [x] Security overview page
- [x] Locked accounts view (**UI refined: single search filter with increased width (`max-w-md`), styling aligned with other tables, sonner toasts for notifications, "Action" column header, standardized button style, "Unlock Account" button now has a confirmation dialog styled with `font-montserrat`, "Successful Attempts" column removed**)
- [x] Users management (**Enhanced with client-side search and dropdown filters for role & security key status. Filters are part of the `DataTable` via a `toolbar` prop. Filter controls use `font-montserrat`. Security key filter labels updated.**)
- [x] Audit logs view
- [x] Settings page

### Security Features
- [x] Security key management
- [x] Locked accounts monitoring (**Improved data table UI: single search with `max-w-md`, "Action" column, standardized button style, unlock confirmation modal with consistent styling, "Successful Attempts" column removed**)
- [x] Audit logging system
- [x] User activity tracking

### AI Integration
- [x] AI chat implementation ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1))
- [x] AI providers setup
- [x] AI tools integration
- [x] Dynamic AI Model Availability via USB Detection:
    - Implemented a local Python helper application (`../backend/usb_detector.py`) using WebSockets to detect "normal" (non-WebAuthn) USB device connections.
    - Frontend chat page ([`src/app/chat/page.tsx`](src/app/chat/page.tsx:1)) connects to this helper and adjusts available AI models for email/password authenticated users based on USB status.
    - Users logged in via WebAuthn security keys retain full model access irrespective of normal USB status.
    - Resolved Python `websockets` library v15.0.1 API incompatibilities.

### UI/UX Enhancements
- [x] Implemented Dark/Light Theme:
    - Added `next-themes` for theme management.
    - Created `ThemeProvider` (with corrected `ThemeProviderProps` import) and `ThemeToggleButton` components.
    - Defined CSS variables in `globals.css` for light/dark modes, primary color `#e60053`, dark background `#0b0a0a`, and chart color palette.
    - Integrated theme toggle into the main header (`src/components/header.tsx`) and dashboard layout (`src/app/dashboard/layout.tsx`) for universal visibility.
- [x] Styling Consistency & Fixes:
    - Applied `rounded-xl` to most `Button` and `Input` components globally.
    - Updated `Textarea` component wrapper to `rounded-xl`.
    - Chat textarea submit button (`src/components/textarea.tsx`) now uses primary color background and foreground text.
    - User-sent chat messages (`src/components/message.tsx`) now have primary color background and foreground text.
    - "Login with Security Key" button (`src/app/login/page.tsx`) now has primary color border.
- [x] Dashboard Sidebar Enhancement:
    - Updated `src/components/app-sidebar.tsx` to use `collapsible="icon"` mode.
    - Sidebar now collapses to show only icons, with text labels hidden (using conditional rendering and opacity/width classes for robustness).
    - Tooltips display item names on hover when collapsed.
    - Added specific classes to `SidebarMenuButton` and its child `<a>` tag to improve icon centering in collapsed view.

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
    *   [ ] Refine USB device detection in `usb_detector.py` to more accurately distinguish between generic USBs and specific WebAuthn keys (currently uses a placeholder).
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