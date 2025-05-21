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
  useSidebar, // Import useSidebar
} from "@/components/ui/sidebar"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip" // Import Tooltip components

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
  const { state } = useSidebar() // Get sidebar state

  const isItemActive = (itemUrl: string) => {
    // For nested routes, make sure it's an exact match for overview
    if (itemUrl === '/dashboard' && pathname !== '/dashboard') {
      return false
    }
    // For other routes, check if the pathname starts with the item URL and is followed by '/' or end of string
    return pathname.startsWith(itemUrl) && (pathname === itemUrl || pathname.charAt(itemUrl.length) === '/')
  }

  return (
    <Sidebar collapsible="icon"> {/* Enable icon collapse */}
      <SidebarContent>
        <SidebarGroup>
          {/* Updated text size for label */}
          <SidebarGroupLabel className="text-base">Argus AI</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {items.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <SidebarMenuButton
                        asChild
                        isActive={isItemActive(item.url)}
                        className={state === "collapsed" ? "justify-center" : ""}
                      >
                        <a href={item.url} className={`flex items-center ${state === "expanded" ? "gap-2" : "justify-center w-full"}`}>
                          <item.icon className="h-4 w-4" />
                          <span className={`text-sm ${state === "expanded" ? "opacity-100" : "opacity-0 w-0 hidden"}`}>{item.title}</span>
                        </a>
                      </SidebarMenuButton>
                    </TooltipTrigger>
                    {state === "collapsed" && (
                      <TooltipContent side="right">
                        <p>{item.title}</p>
                      </TooltipContent>
                    )}
                  </Tooltip>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  )
}