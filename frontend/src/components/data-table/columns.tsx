"use client"

import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { MoreHorizontal, Eye, Edit3, Trash2, LockOpen } from "lucide-react"
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
  account_locked: boolean // New field for account lock status
}

export const columns: ColumnDef<User, unknown>[] = [
  {
    id: "select",
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllPageRowsSelected() ||
          (table.getIsSomePageRowsSelected() && "indeterminate")
        }
        onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
        aria-label="Select all"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(value) => row.toggleSelected(!!value)}
        aria-label="Select row"
      />
    ),
    enableSorting: false,
    enableHiding: false,
  },
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
            <Badge variant="outline" className="text-red-700 dark:text-red-400 border-red-300 dark:border-red-700">
              Inactive
            </Badge>
        )
      } else {
        return (
            <Badge variant="outline" className="text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700">
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
    accessorKey: "account_locked",
    header: "Account Status",
    cell: ({ row }) => {
      const isLocked = row.getValue("account_locked") as boolean

      if (isLocked) {
        return (
          <Badge variant="destructive" className="bg-red-100 text-red-700 dark:bg-transparent dark:text-red-300 border-red-300 dark:border-red-700">
            Locked
          </Badge>
        )
      } else {
        return (
          <Badge variant="outline" className="text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
            Unlocked
          </Badge>
        )
      }
    },
  },
  {
    id: "actions",
    cell: ({ row, table }) => {
      const router = useRouter()
      const user = row.original
      const { setSelectedUser, setIsDeleteDialogOpen, setIsEditUserDialogOpen, setIsUnlockAccountDialogOpen } = table.options.meta as any

      return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="font-montserrat border-0 shadow-lg">
              <DropdownMenuItem onClick={() => router.push(`/dashboard/users/${user.id}`)}>
                <Eye className="mr-2 h-4 w-4" />
                View Details
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => {
                setSelectedUser(user);
                setIsEditUserDialogOpen(true);
              }}>
                <Edit3 className="mr-2 h-4 w-4" />
                Edit User
              </DropdownMenuItem>
              {user.account_locked && (
                <DropdownMenuItem onClick={() => {
                  setSelectedUser(user);
                  setIsUnlockAccountDialogOpen(true);
                }}>
                  <LockOpen className="mr-2 h-4 w-4" />
                  Unlock Account
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                  onClick={() => {
                    setSelectedUser(user);
                    setIsDeleteDialogOpen(true);
                  }}
                  className="text-red-600 focus:text-red-600 focus:bg-red-50 dark:focus:bg-red-900 dark:focus:text-red-400"
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete User
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
      )
    },
  },
]
