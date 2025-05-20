# Technical Context: Argus AI Secure

## Development Environment

### Core Technologies
- Next.js 15.2.4 with App Router
- React 19.0.0
- TypeScript 5
- Tailwind CSS 4

### Build & Development
- Development: `next dev --turbopack` (using Turbopack for faster builds)
- Production Build: `next build`
- Production Start: `next start`
- Linting: `next lint`

## Key Dependencies

### UI Framework
- Radix UI Components:
  - Alert Dialog
  - Avatar
  - Dialog
  - Dropdown Menu
  - Label
  - Progress
  - Scroll Area
  - Select
  - Separator
  - Tabs
  - Tooltip
- Class Variance Authority & Tailwind Merge for styling utilities
- Lucide React for icons
- Sonner for toast notifications (**Standardized for user feedback**)

### Authentication & Security
- SimpleWebAuthn Browser SDK (v13.1.0)
- Axios for HTTP requests
- Backend: Flask (Python) for API endpoints including authentication and account management.

### Data Management & Display
- Zustand for state management
- TanStack React Table for data grids
- Recharts for data visualization
- Date-fns for date manipulation

### AI Integration
- AI SDK (Groq provider)
- AI SDK React components
- React Markdown with GFM for content rendering

## Development Tools
- TypeScript with React types
- Tailwind CSS tooling
- Vercel OpenTelemetry for monitoring

## Configuration Files
- `next.config.ts`: Next.js configuration
- `tsconfig.json`: TypeScript settings
- `components.json`: UI component configuration
- `postcss.config.mjs`: PostCSS setup for Tailwind

## Development Patterns
1.  **Type Safety**
    - Strong TypeScript typing
    - Type-safe API requests
    - Component prop validation

2.  **Styling**
    - Tailwind CSS for utility-first styling
    - Component-level style composition using `Card` and `CardContent` for consistent table layouts.
    - CSS animation utilities

3.  **Performance**
    - Turbopack for fast development
    - Optimized production builds
    - Component-level code splitting

4.  **Code Quality**
    - ESLint configuration
    - TypeScript strict mode
    - Consistent code formatting

5.  **User Feedback**
    - Standardized use of `sonner` for toast notifications for actions like account unlock, user creation, etc.