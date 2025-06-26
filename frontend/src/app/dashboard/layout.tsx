"use client"

import { Bell, LogOut, Search, Settings } from "lucide-react" // Added Search and Settings
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { SidebarProvider, SidebarTrigger, SidebarInset } from "@/components/ui/sidebar"
import { Input } from "@/components/ui/input"
import { AppSidebar } from "@/components/app-sidebar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { ThemeToggleButton } from "@/components/theme-toggle-button";

// Sample security alerts data for notifications
const securityAlertsData = [
  {
    id: 1,
    type: "High Risk Login",
    user: "james_s",
    details: "Login attempt from unrecognized location",
    time: "4 minutes ago",
    severity: "High",
  },
  {
    id: 2,
    type: "Multiple Failed Attempts",
    user: "guest123",
    details: "5 failed login attempts",
    time: "35 minutes ago",
    severity: "Medium",
  },
  {
    id: 3,
    type: "Security Key Issue",
    user: "mike_l",
    details: "Authentication counter regression",
    time: "2 hours ago",
    severity: "Low",
  },
]

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const router = useRouter()

  const handleLogout = () => {
    sessionStorage.removeItem("user")
    router.push("/home")
  }

  return (
    <SidebarProvider>
      {/* Add font-montserrat class here */}
      <div className="relative flex min-h-screen font-montserrat w-full">
        <AppSidebar />
        <SidebarInset>
          <header className="bg-background/80 sticky top-0 z-30 flex h-14 items-center gap-3 px-4 backdrop-blur-xl lg:h-[60px]"> {/* Removed border-b */}
            <SidebarTrigger className="size-9 p-0 flex items-center justify-center border border-sidebar-border bg-sidebar shadow-xs hover:bg-accent hover:text-accent-foreground dark:hover:bg-input/50 rounded-full" /> {/* Removed md:hidden, changed to rounded-xl and bg-sidebar */}

            {/* Search Section */}
            <div className="ms-auto lg:ms-0 lg:flex-1"> {/* Adjusted for alignment */}
              <div className="relative hidden max-w-sm flex-1 lg:block">
                <Search className="text-sidebar-foreground/70 absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2" /> {/* Adjusted icon color for sidebar bg */}
                <Input
                  type="search"
                  placeholder="Search..."
                  className="h-9 w-full cursor-pointer rounded-full border border-sidebar-border bg-transparent text-sidebar-foreground placeholder:text-sidebar-foreground/70 pr-4 pl-10 text-sm shadow-xs dark:border-input" // Changed to rounded-xl, bg-sidebar, added text/placeholder colors
                />
                {/* Command K shortcut - visual only for now */}
                <div className="absolute top-1/2 right-2 hidden -translate-y-1/2 items-center gap-0.5 rounded-sm bg-zinc-200 p-1 font-mono text-xs font-medium sm:flex dark:bg-neutral-700">
                  <kbd>⌘</kbd>
                  <kbd>K</kbd>
                </div>
              </div>
              <div className="block lg:hidden">
                <Button variant="outline" size="icon" className="size-9 border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50">
                  <Search className="h-4 w-4" />
                  <span className="sr-only">Search</span>
                </Button>
              </div>
            </div>

            {/* Right Aligned Icons */}
            <div className="flex items-center gap-3">
              <ThemeToggleButton />
              <Button variant="outline" size="icon" className="size-9 border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 relative">
                <Bell className="h-4 w-4" />
                <span className="bg-destructive absolute -end-0.5 -top-0.5 block size-2 shrink-0 rounded-xl"></span>
                <span className="sr-only">Notifications</span>
              </Button>
              <Button variant="outline" size="icon" className="size-9 border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50">
                <Settings className="h-4 w-4" />
                <span className="sr-only">Settings</span>
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="rounded-xl">
                    <Avatar>
                      <AvatarFallback className="bg-primary text-white">SA</AvatarFallback>
                    </Avatar>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="font-montserrat">
                  <DropdownMenuLabel>Admin Account</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem>Profile Settings</DropdownMenuItem>
                  <DropdownMenuItem>Security Settings</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={handleLogout} className="text-red-500 cursor-pointer">
                    <LogOut className="h-4 w-4 mr-2" />
                    Logout
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </header>
          <main className="p-4 sm:px-6 sm:py-8">
            {children}
          </main>
        </SidebarInset>
      </div>
    </SidebarProvider>
  )
}
