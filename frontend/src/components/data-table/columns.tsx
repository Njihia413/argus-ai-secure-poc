"use client"

import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MoreHorizontal } from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useRouter } from "next/navigation"

export type User = {
  id: number
  username: string
  firstName: string
  lastName: string
  role: string
  hasSecurityKey: boolean
  lastLogin: string | null
  loginAttempts: number
  failedAttempts: number
}

export const columns: ColumnDef<User>[] = [
  {
    accessorKey: "firstName",
    header: "First Name",
  },
  {
    accessorKey: "lastName",
    header: "Last Name",
  },
  {
    accessorKey: "role",
    header: "Role",
    cell: ({ row }) => {
      return (
        <Badge variant="outline" className="bg-slate-100">
          {row.getValue("role")}
        </Badge>
      )
    },
  },
  {
    accessorKey: "hasSecurityKey",
    header: "Security Key",
    cell: ({ row }) => {
      const hasKey = row.getValue("hasSecurityKey")
      return hasKey ? (
        <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
          Registered
        </Badge>
      ) : (
        <Badge variant="outline" className="bg-amber-50 text-amber-700 border-amber-200">
          Not Registered
        </Badge>
      )
    },
  },
  {
    accessorKey: "lastLogin",
    header: "Last Login",
    cell: ({ row }) => {
      const lastLogin = row.getValue("lastLogin")
      if (!lastLogin) return <span className="text-sm text-muted-foreground">Not available</span>

      return (
        <div className="text-sm text-muted-foreground">
          <div>
            {new Date(lastLogin as string).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            })}
          </div>
          <div>
            {new Date(lastLogin as string).toLocaleTimeString('en-US', {
              hour: 'numeric',
              minute: '2-digit',
              hour12: true
            })}
          </div>
        </div>
      )
    },
  },
  {
    accessorKey: "loginAttempts",
    header: "Successful Logins",
    cell: ({ row }) => {
      const attempts = row.getValue("loginAttempts")
      return (
        <Badge
          variant="outline"
          className={`${Number(attempts) > 0 ? "bg-green-50 text-green-700 border-green-200" : "bg-slate-100"}`}
        >
          {attempts}
        </Badge>
      )
    },
  },
  {
    accessorKey: "failedAttempts",
    header: "Failed Attempts",
    cell: ({ row }) => {
      const attempts = row.getValue("failedAttempts")
      return (
        <Badge
          variant="outline"
          className={`${Number(attempts) > 0 ? "bg-red-50 text-red-700 border-red-200" : "bg-slate-100"}`}
        >
          {attempts}
        </Badge>
      )
    },
  },
  {
    id: "actions",
    cell: ({ row }) => {
      const router = useRouter()
      const user = row.original

      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="font-montserrat">
            <DropdownMenuItem onClick={() => router.push(`/dashboard/users/${user.id}`)}>
              View Details
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-red-600">
              Delete User
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )
    },
  },
]