"use client"

import { ColumnDef } from "@tanstack/react-table"
import { Button } from "@/components/ui/button"
import { ArrowUpDown } from "lucide-react"
import { API_URL } from "@/app/utils/constants"
import { toast } from "sonner"

export type LockedAccount = {
  id: number
  username: string
  email: string
  firstName: string
  lastName: string
  locked_time: string  
  failed_attempts: number  
  successful_attempts: number  
  total_attempts: number 
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
    accessorKey: "firstName",
    header: "First Name"
  },
  {
    accessorKey: "lastName",
    header: "Last Name"
  },
  {
    accessorKey: "email",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Email
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    }
  },
  {
    accessorKey: "failed_attempts",
    header: "Failed Attempts",
    cell: ({ row }) => {
      return (
        <div className="font-medium text-red-600">
          {row.getValue("failed_attempts")}
        </div>
      )
    }
  },
  {
    accessorKey: "successful_attempts",
    header: "Successful Attempts",
    cell: ({ row }) => {
      return (
        <div className="font-medium text-green-600">
          {row.getValue("successful_attempts")}
        </div>
      )
    }
  },
  {
    accessorKey: "locked_time",
    header: "Locked At",
    cell: ({ row }) => {
      const timestamp = row.getValue("locked_time") as string
      return timestamp ? new Date(timestamp).toLocaleString() : "N/A"
    }
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
              // Get auth token
              const userStr = sessionStorage.getItem('user')
              if (!userStr) {
                throw new Error('User not authenticated')
              }
              
              const user = JSON.parse(userStr)
              const authToken = user.authToken

              const response = await fetch(`${API_URL}/users/${account.id}/unlock`, {
                headers: {
                  'Authorization': `Bearer ${authToken}`,
                  'Content-Type': 'application/json'
                },
                method: 'POST',
              })
              
              if (!response.ok) {
                throw new Error('Failed to unlock account')
              }
              
              toast.success("Account unlocked successfully")
              window.location.reload()
            } catch (error) {
              console.error('Error unlocking account:', error)
              toast.error("Failed to unlock account. Please try again.")
            }
          }}
        >
          Unlock Account
        </Button>
      )
    }
  }
]