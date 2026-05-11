"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ChevronRight, ChevronDown } from "lucide-react"
import React from "react"
import { useAuth } from "@/app/utils/useAuth"
import { ADMIN_NAV_SECTIONS } from "@/app/utils/admin-nav"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

export function AppSidebar({ allowedSections }: { allowedSections?: string[] }) {
  const pathname = usePathname()
  const { hasElevatedAccess } = useAuth()
  const { state } = useSidebar()

  const isActive = (url: string): boolean => {
    if (url === "/dashboard") return pathname === "/dashboard"
    return pathname === url || pathname.startsWith(url + "/")
  }

  const visibleSections = ADMIN_NAV_SECTIONS.filter((s) => {
    if (s.elevated && !hasElevatedAccess) return false
    if (allowedSections !== undefined && allowedSections.length > 0 && !allowedSections.includes(s.slug)) return false
    return true
  })

  const regularItems = visibleSections.filter((s) => !s.elevated)
  const elevatedItems = visibleSections.filter((s) => s.elevated)

  const renderItem = (item: (typeof ADMIN_NAV_SECTIONS)[number]) => (
    <SidebarMenuItem key={item.slug}>
      <Tooltip>
        <TooltipTrigger asChild>
          <SidebarMenuButton
            asChild
            isActive={isActive(item.url)}
            className={state === "collapsed" ? "justify-center" : ""}
          >
            <a
              href={item.url}
              className={`flex items-center ${state === "expanded" ? "gap-2" : "justify-center w-full"}`}
            >
              <item.icon className="h-4 w-4" />
              <span
                className={`text-sm ${state === "expanded" ? "opacity-100" : "opacity-0 w-0 hidden"}`}
              >
                {item.label}
              </span>
            </a>
          </SidebarMenuButton>
        </TooltipTrigger>
        {state === "collapsed" && (
          <TooltipContent side="right">
            <p>{item.label}</p>
          </TooltipContent>
        )}
      </Tooltip>
    </SidebarMenuItem>
  )

  return (
    <Sidebar collapsible="icon" variant="floating" className="rounded-xl">
      <SidebarContent className="flex flex-col">
        <div className="flex-grow">
          <SidebarGroup>
            <SidebarGroupLabel className="px-2 py-1 text-xl font-bold mb-6">
              <Link href="/dashboard" className="hover:opacity-80 transition-opacity">
                Argus AI Secure
              </Link>
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {regularItems.map(renderItem)}
                {elevatedItems.length > 0 && (
                  <>
                    <SidebarGroupLabel className="px-2 py-1 text-xs font-semibold uppercase text-muted-foreground tracking-wider mt-4">
                      Elevated Access
                    </SidebarGroupLabel>
                    {elevatedItems.map(renderItem)}
                  </>
                )}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </div>
      </SidebarContent>
    </Sidebar>
  )
}
