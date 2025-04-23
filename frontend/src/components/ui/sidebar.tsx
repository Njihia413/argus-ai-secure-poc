"use client"

import * as React from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield, Users, AlertTriangle, Settings } from "lucide-react"
import { cn } from "@/lib/utils"

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"

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

export function Sidebar({ className }: React.HTMLAttributes<HTMLDivElement>) {
  const pathname = usePathname()

  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="ghost" className="h-9 w-9 p-0 lg:hidden">
          <Shield className="h-6 w-6" />
          <span className="sr-only">Toggle sidebar</span>
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-64 p-0">
        <SheetHeader className="p-4 border-b">
          <SheetTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-teal-600" />
            <span>SecureAuth PoC</span>
          </SheetTitle>
        </SheetHeader>
        <ScrollArea className="my-4 h-[calc(100vh-8rem)] pb-10">
          <div className="flex flex-col gap-1 p-2">
            {sidebarNavItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground",
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
      </SheetContent>
    </Sheet>
  )
}