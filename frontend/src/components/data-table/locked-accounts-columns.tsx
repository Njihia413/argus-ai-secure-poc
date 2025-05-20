"use client"

import { ColumnDef } from "@tanstack/react-table"
import { Button } from "@/components/ui/button"
import { ArrowUpDown } from "lucide-react"

export type LockedAccount = {
  id: string
  username: string
  email: string
  lastLoginAttempt: string
  failedAttempts: number
  lockedAt: string
}

export const columns: ColumnDef<LockedAccount>[] = [
  {
    accessorKey: "username",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Username
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    }
  },
  {
    accessorKey: "email",
    header: "Email"
  },
  {
    accessorKey: "lastLoginAttempt",
    header: "Last Login Attempt"
  },
  {
    accessorKey: "failedAttempts",
    header: "Failed Attempts"
  },
  {
    accessorKey: "lockedAt",
    header: "Locked At"
  },
  {
    id: "actions",
    cell: ({ row }) => {
      const account = row.original
      
      return (
        <Button
          variant="outline"
          size="sm"
          onClick={async () => {
            try {
              const response = await fetch(`/api/accounts/${account.id}/unlock`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                }
              })
              
              if (!response.ok) {
                throw new Error('Failed to unlock account')
              }
              
              // Refresh data after unlock
              window.location.reload()
            } catch (error) {
              console.error('Error unlocking account:', error)
            }
          }}
        >
          Unlock Account
        </Button>
      )
    }
  }
]