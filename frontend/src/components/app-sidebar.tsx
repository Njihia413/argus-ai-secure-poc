"use client"

import { usePathname } from "next/navigation"
import { LayoutDashboard, Users, Shield, Settings, ClipboardList, Lock } from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

const items = [
  {
    title: "Overview",
    url: "/dashboard",
    icon: LayoutDashboard,
  },
  {
    title: "Users",
    url: "/dashboard/users",
    icon: Users,
  },
  {
    title: "Security",
    url: "/dashboard/security",
    icon: Shield,
  },
  {
    title: "Audit Logs",
    url: "/dashboard/audit-logs",
    icon: ClipboardList,
  },
  {
    title: "Settings",
    url: "/dashboard/settings",
    icon: Settings,
  },
  {
    title: "Locked Accounts",
    url: "/dashboard/locked-accounts",
    icon: Lock,
  },
]

export function AppSidebar() {
  const pathname = usePathname()

  const isItemActive = (itemUrl: string) => {
    // For nested routes, make sure it's an exact match for overview
    if (itemUrl === '/dashboard' && pathname !== '/dashboard') {
      return false
    }
    // For other routes, check if the pathname starts with the item URL and is followed by '/' or end of string
    return pathname.startsWith(itemUrl) && (pathname === itemUrl || pathname.charAt(itemUrl.length) === '/')
  }

  return (
    <Sidebar>
      <SidebarContent>
        <SidebarGroup>
          {/* Updated text size for label */}
          <SidebarGroupLabel className="text-base">Argus AI</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {items.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    asChild
                    isActive={isItemActive(item.url)}
                  >
                    <a href={item.url} className="flex items-center gap-2">
                      <item.icon className="h-4 w-4" />
                      <span className="text-sm">{item.title}</span>
                    </a>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  )
}