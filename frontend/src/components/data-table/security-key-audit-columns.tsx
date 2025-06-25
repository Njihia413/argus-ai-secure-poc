"use client"

import { ColumnDef } from "@tanstack/react-table"
import { ArrowUpDown } from "lucide-react"

import { Button } from "@/components/ui/button"

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
  },
  {
    accessorKey: "details",
    header: "Details",
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
      const timestamp = row.getValue("timestamp") as string
      return new Date(timestamp).toLocaleString()
    },
  },
  {
    accessorKey: "performedBy",
    header: "Performed By",
    cell: ({ row }) => {
      const performedBy = row.original.performedBy
      return performedBy ? performedBy.username : "System"
    },
  },
]