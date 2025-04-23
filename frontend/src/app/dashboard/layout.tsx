"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"

interface SidebarNavProps extends React.HTMLAttributes<HTMLDivElement> {
  items: {
    href: string
    title: string
    icon: React.ReactNode
  }[]
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const pathname = usePathname()
  
  const sidebarNavItems = [
    {
      title: "Overview",
      href: "/dashboard",
      icon: <Shield className="h-4 w-4" />,
    },
    {
      title: "Users",
      href: "/dashboard/users",
      icon: <Users className="h-4 w-4" />,
    },
    {
      title: "Security",
      href: "/dashboard/security",
      icon: <AlertTriangle className="h-4 w-4" />,
    },
    {
      title: "Settings",
      href: "/dashboard/settings",
      icon: <Settings className="h-4 w-4" />,
    },
  ]

  return (
    <div className="flex min-h-screen">
      <div className="hidden border-r bg-background md:block md:w-64">
        <div className="flex h-16 items-center gap-2 border-b px-4">
          <Shield className="h-6 w-6 text-teal-600" />
          <span className="text-lg font-bold">SecureAuth PoC</span>
        </div>
        <ScrollArea className="h-[calc(100vh-4rem)] px-3 py-2">
          <div className="flex flex-col gap-1">
            {sidebarNavItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground",
                  pathname === item.href
                    ? "bg-accent text-accent-foreground"
                    : "transparent"
                )}
              >
                {item.icon}
                {item.title}
              </Link>
            ))}
          </div>
        </ScrollArea>
      </div>
      <div className="flex-1">
        <header className="sticky top-0 z-50 flex h-16 items-center gap-4 border-b bg-background px-4 md:px-6 shadow-sm">
          <div className="flex-1" />
          <div className="flex items-center gap-4">
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
                <DropdownMenuContent align="end" className="w-80">
                  <DropdownMenuLabel>Notifications</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {securityAlertsData.slice(0, 3).map((alert) => (
                    <DropdownMenuItem key={alert.id} className="cursor-pointer flex flex-col items-start">
                      <div className="flex items-center w-full">
                        <AlertTriangle
                          className={`h-4 w-4 mr-2 ${
                            alert.severity === "High"
                              ? "text-red-500"
                              : alert.severity === "Medium"
                                ? "text-amber-500"
                                : "text-blue-500"
                          }`}
                        />
                        <span className="font-medium">{alert.type}</span>
                        <span className="ml-auto text-xs text-muted-foreground">{alert.time}</span>
                      </div>
                      <span className="text-sm text-muted-foreground mt-1">
                        User: {alert.user} - {alert.details}
                      </span>
                    </DropdownMenuItem>
                  ))}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem className="cursor-pointer justify-center text-teal-600">
                    View all notifications
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="rounded-full">
                  <Avatar>
                    <AvatarFallback className="bg-teal-600 text-white">SA</AvatarFallback>
                  </Avatar>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
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
        <main className="container mx-auto p-4 sm:px-6 sm:py-8">
          {children}
        </main>
      </div>
    </div>
  )
}