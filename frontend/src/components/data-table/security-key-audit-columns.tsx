"use client"

import { ColumnDef } from "@tanstack/react-table"
import { ArrowUpDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"


// Interface for the audit log specific to a security key
export interface SecurityKeyAuditLog {
  id: number
  action: string
  details: string | null
  timestamp: string
  performedBy: {
    id: number
    username: string
  }
}

export const columns: ColumnDef<SecurityKeyAuditLog>[] = [
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
    accessorKey: "action",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Action
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    },
    cell: ({ row }) => {
      const action = row.getValue("action") as string
      const actionStyles = {
        "initial-register": "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700",
        "re-register": "text-blue-700 dark:text-blue-400 border-blue-300 dark:border-blue-700",
        "deactivate": "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700",
        "reset": "text-yellow-700 dark:text-yellow-400 border-yellow-300 dark:border-yellow-700",
        "reassign": "text-purple-700 dark:text-purple-400 border-purple-300 dark:border-purple-700"
      }
      
      const actionLabel = {
        "initial-register": "Initial Registration",
        "re-register": "Re-Registration",
        "deactivate": "Deactivation",
        "reset": "Reset",
        "reassign": "Reassignment"
      }[action] || action

      return (
        <Badge
          variant="outline"
          className={`${actionStyles[action as keyof typeof actionStyles] || ""} bg-transparent`}
        >
          {actionLabel}
        </Badge>
      )
    }
  },
  {
    accessorKey: "details",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Details
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    },
  },
  {
    accessorKey: "timestamp",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Timestamp
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    },
    cell: ({ row }) => {
      const timestamp = row.getValue("timestamp") as string;
      if (!timestamp) return <span className="text-sm text-muted-foreground">Not available</span>;

      return (
        <div className="text-sm">
          <div className="text-foreground">
            {new Date(timestamp).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            })}
          </div>
          <div className="text-muted-foreground">
            {new Date(timestamp).toLocaleTimeString('en-US', {
              hour: 'numeric',
              minute: '2-digit',
              hour12: true
            })}
          </div>
        </div>
      );
    },
  },
  {
    accessorKey: "performedBy",
    header: ({ column }) => {
      return (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Performed By
          <ArrowUpDown className="ml-2 h-4 w-4" />
        </Button>
      )
    },
    cell: ({ row }) => {
      const performedBy = row.original.performedBy
      return (
        <span className="font-medium">
          {performedBy ? performedBy.username : "System"}
        </span>
      )
    },
  },
]