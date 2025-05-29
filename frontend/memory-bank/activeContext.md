# Active Context: Argus AI Secure

## Current Focus
Based on open files and recent activity, development is focused on security management features, UI enhancements for the dashboard, and theme refinements.

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
        *   Added new CSS variables to use sidebar background colors for card borders:
            *   `--card-border-light: var(--sidebar-bg-light);`
            *   `--card-border-dark: var(--sidebar-bg-dark);`
            *   `--card-border-themed` (points to the theme-specific variable).

4.  **Dashboard Layout ([`src/app/dashboard/layout.tsx`](src/app/dashboard/layout.tsx:1))**
    *   Search Input: The `Input` component for search now has a `rounded-xl` class.
    *   Sidebar Trigger: The `SidebarTrigger` button now has `rounded-full` and `bg-sidebar` classes, with `border-sidebar-border`.

5.  **Sidebar Component ([`src/components/ui/sidebar.tsx`](src/components/ui/sidebar.tsx:1))**
    *   Active Menu Item: The `sidebarMenuButtonVariants` were updated. Active items (`data-[active=true]`) now have `rounded-full`. Non-active items retain `rounded-xl`.

6.  **Card Component ([`src/components/ui/card.tsx`](src/components/ui/card.tsx:1))**
    *   Border Color: Updated to use `border-[var(--card-border-themed)]`.
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
1.  **Key Reassignment Security:** Implemented backend check to prevent reassigning a key to a user who already has an active one. Frontend toast notification added for this specific error.
2.  **Dashboard Styling:**
    *   Sidebar background colors updated for both light (`#F5F5F1`) and dark (`#1c1819`) modes.
    *   Dashboard search input and sidebar trigger button styling refined (border radius, background).
    *   Active sidebar menu items now have a `rounded-full` border radius.
    *   Overview cards on the dashboard now use a "to top" gradient based on the primary theme color, with borders matching the sidebar background. Card border radius increased to `rounded-2xl`. Text colors adjusted for visibility.
    *   Removed white borders from pie charts in dark mode.
    *   Login Attempts chart refactored to use shadcn `ChartContainer` and `Select` for filters, with styling and functionality aligned with the provided interactive example.
3.  **Login Page UI:** The "OR" divider on the login page was updated for clarity and modern styling. The "Login with Security Key" button background was also updated to match input fields.
4.  **Theming Variables:** Introduced new CSS variables in `globals.css` for card gradients and card borders to ensure theme adaptability.

## Active Technical Patterns
1.  **Data Table Pattern:** Consistent use for displaying security-related information, with features like filtering, pagination, and standardized action handling.
2.  **Security Patterns:** WebAuthn, locked account management, audit logging, refined key reassignment logic.
3.  **Layout Patterns:** Dashboard layout with a collapsible, theme-aware sidebar.
4.  **Notification Pattern:** Standardized use of `sonner` for toast notifications.
5.  **Theming Pattern:** `next-themes` for theme management, extensive use of CSS custom properties for theme-specific styling (colors, gradients, borders, radii).

## Current Considerations
1.  **UI/UX:**
    *   Ensuring the new card gradients and border colors look good and are accessible in both themes.
    *   Verifying text visibility and contrast across all themed components.
    *   Confirming the increased card border radius (`rounded-2xl`) is visually appealing.
2.  **Backend Logic:** Confirming the security key reassignment logic correctly handles all edge cases.
3.  **CSS Specificity:** Ensuring Tailwind JIT compiler correctly interprets and applies styles using CSS variables, especially for gradients and borders.