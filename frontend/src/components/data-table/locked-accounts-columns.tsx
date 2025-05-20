"use client"

import React, { useState } from "react" // Import useState
import { ColumnDef } from "@tanstack/react-table"
import { Button } from "@/components/ui/button"
import { ArrowUpDown } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose, // Import DialogClose
} from "@/components/ui/dialog"
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
    accessorKey: "locked_time",
    header: "Locked At",
    cell: ({ row }) => {
      const timestamp = row.getValue("locked_time") as string
      return timestamp ? new Date(timestamp).toLocaleString() : "N/A"
    }
  },
  {
    id: "actions",
    header: "Action",
    cell: ({ row }) => {
      const account = row.original
      const [isDialogOpen, setIsDialogOpen] = useState(false)
      const [isLoading, setIsLoading] = useState(false)

      const handleUnlockAccount = async () => {
        setIsLoading(true)
        try {
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
            const errorData = await response.json()
            throw new Error(errorData.error || 'Failed to unlock account')
          }
          
          toast.success("Account unlocked successfully")
          setIsDialogOpen(false) // Close dialog on success
          window.location.reload() // Or update table data state
        } catch (error) {
          console.error('Error unlocking account:', error)
          toast.error((error as Error).message || "Failed to unlock account. Please try again.")
        } finally {
          setIsLoading(false)
        }
      }
      
      return (
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button
              className="bg-black hover:bg-black/90 text-white"
              size="sm"
            >
              Unlock Account
            </Button>
          </DialogTrigger>
          <DialogContent className="font-montserrat sm:max-w-[425px]">
            <DialogHeader>
              <DialogTitle>Confirm Unlock</DialogTitle>
              <DialogDescription>
                Are you sure you want to unlock the account for {account.username} ({account.firstName} {account.lastName})?
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline" disabled={isLoading}>Cancel</Button>
              </DialogClose>
              <Button
                onClick={handleUnlockAccount}
                className="bg-black hover:bg-black/90 text-white"
                disabled={isLoading}
              >
                {isLoading ? "Unlocking..." : "Confirm Unlock"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )
    }
  }
]