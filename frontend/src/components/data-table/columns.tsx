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
  nationalId: string
  username: string
  firstName: string
  middlename: string | null
  lastName: string
  email: string
  role: string
  hasSecurityKey: boolean
  securityKeyStatus: string | null // Add this new field for status (active, inactive, null)
  lastLogin: string | null
  loginAttempts: number
  failedAttempts: number
}

export const columns: ColumnDef<User, unknown>[] = [
  {
    accessorKey: "firstName",
    header: "First Name",
  },
  {
    accessorKey: "middlename",
    header: "Middle Name",
    cell: ({ row }) => {
      const middlename = row.getValue("middlename")
      return middlename || "—"
    },
  },
  {
    accessorKey: "lastName",
    header: "Last Name",
  },
  {
    accessorKey: "nationalId",
    header: "National ID",
  },
  {
    accessorKey: "email",
    header: "Email",
  },
  {
    accessorKey: "role",
    header: "Role",
    cell: ({ row }) => {return (
        <Badge variant="outline">
          {row.getValue("role")}
        </Badge>
    )
    },
  },
  {
    // Updated to use securityKeyStatus instead of securityKeyCount
    accessorKey: "securityKeyStatus",
    header: "Security Key",
    filterFn: (row, id, value) => {
      if (value === "all") return true
      if (value === "active") return row.getValue(id) === "active"
      if (value === "inactive") return row.getValue(id) === "inactive"
      if (value === "none") return row.getValue(id) === null
      return true
    },
    cell: ({ row }) => {
      const keyStatus = row.getValue("securityKeyStatus") as string | null

      if (keyStatus === "active") {
        return (
            <Badge variant="outline" className="text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
              Active
            </Badge>
        )
      } else if (keyStatus === "inactive") {
        return (
            <Badge variant="outline" className="text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700">
              Inactive
            </Badge>
        )
      } else {
        return (
            <Badge variant="outline" className="text-red-700 dark:text-red-400 border-red-300 dark:border-red-700">
              None
            </Badge>
        )
      }
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
              className={`${(attempts as number) > 0 ? "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700" : ""}`}
          >
            {attempts as number}
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
              className={`${(attempts as number) > 0 ? "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700" : ""}`}
          >
            {attempts as number}
          </Badge>
      )
    },
  },
  {
    id: "actions",
    cell: ({ row, table }) => {
      const router = useRouter()
      const user = row.original
      const { setSelectedUser, setIsDeleteDialogOpen } = table.options.meta as any

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
              <DropdownMenuItem onClick={() => {
                (table.options.meta as any).setSelectedUser(user);
                (table.options.meta as any).setIsEditUserDialogOpen(true);
              }}>
                Edit User
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                  onClick={() => {
                    (table.options.meta as any).setSelectedUser(user);
                    (table.options.meta as any).setIsDeleteDialogOpen(true);
                  }}
                  className="text-red-600"
              >
                Delete User
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
      )
    },
  },
]
