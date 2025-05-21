"use client"

import { Bell, LogOut } from "lucide-react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { SidebarProvider, SidebarTrigger, SidebarInset } from "@/components/ui/sidebar"
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
    router.push("/login")
  }

  return (
    <SidebarProvider>
      {/* Add font-montserrat class here */}
      <div className="relative flex min-h-screen font-montserrat w-full">
        <AppSidebar />
        <SidebarInset>
          <header className="sticky top-0 z-50 flex h-16 items-center gap-4 border-b bg-background px-4 md:px-6 shadow-sm w-full">
            <SidebarTrigger />
            <div className="flex-1" />
            <div className="flex items-center gap-4">
              <ThemeToggleButton />
              <div className="relative">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="relative">
                      <Bell className="h-5 w-5" />
                      <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-red-500 text-xs text-white flex items-center justify-center">
                        3
                      </span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="w-80 font-montserrat">
                    <DropdownMenuLabel>Notifications</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    {securityAlertsData.slice(0, 3).map((alert) => (
                      <DropdownMenuItem key={alert.id} className="cursor-pointer flex flex-col items-start">
                        <div className="flex items-center w-full">
                          <span className="font-medium">{alert.type}</span>
                          <span className="ml-auto text-xs text-muted-foreground">{alert.time}</span>
                        </div>
                        <span className="text-sm text-muted-foreground mt-1">
                          User: {alert.user} - {alert.details}
                        </span>
                      </DropdownMenuItem>
                    ))}
                    <DropdownMenuSeparator />
                    <DropdownMenuItem className="cursor-pointer justify-center text-black">
                      View all notifications
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="rounded-full">
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
