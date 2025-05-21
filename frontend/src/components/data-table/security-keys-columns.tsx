"use client"

import { ColumnDef } from "@tanstack/react-table"
import { MoreHorizontal } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
// import { DataTableColumnHeader } from "./data-table-column-header" // Component does not exist

// Updated data type to match backend and page component
export interface SecurityKey {
  id: string | number;
  model: string | null;
  type: string | null;
  serialNumber: string | null;
  status: "active" | "inactive"; // Simplified status
  registeredOn: string; // ISO date string
  lastUsed: string; // ISO date string or "Never"
  username: string; // Added username
}

export const securityKeysColumns: ColumnDef<SecurityKey>[] = [
  {
    accessorKey: "username",
    header: "User",
    cell: ({ row }) => <div className="font-medium">{row.getValue("username")}</div>,
  },
  {
    accessorKey: "model",
    header: "Model",
    cell: ({ row }) => <div>{row.getValue("model") || "N/A"}</div>,
  },
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }) => <div>{row.getValue("type") || "N/A"}</div>,
  },
  {
    accessorKey: "serialNumber",
    header: "Serial Number",
    cell: ({ row }) => <div>{row.getValue("serialNumber") || "N/A"}</div>,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const status = row.getValue("status") as SecurityKey["status"];
      let badgeClassName = "border-transparent bg-gray-500 text-gray-50"; // Default for unknown
      if (status === "active") {
        // Consistent with user details page: text-green-700 dark:text-green-400 border-green-300 dark:border-green-700
        badgeClassName = "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700 bg-transparent";
      } else if (status === "inactive") {
        // Consistent with user details page: text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700
        badgeClassName = "text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700 bg-transparent";
      }
      return <Badge variant="outline" className={`capitalize ${badgeClassName}`}>{status}</Badge>;
    },
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id));
    },
  },
  {
    accessorKey: "registeredOn",
    header: "Registered On",
    cell: ({ row }) => {
      const date = row.getValue("registeredOn") as string
      return <div>{new Date(date).toLocaleDateString()}</div>
    },
  },
  {
    accessorKey: "lastUsed",
    header: "Last Used",
    cell: ({ row }) => {
      const lastUsed = row.getValue("lastUsed") as string
      if (lastUsed === "Never") {
        return <div>Never</div>
      }
      return <div>{new Date(lastUsed).toLocaleDateString()}</div>
    },
  },
  {
    id: "actions",
    header: "Action", // Added header label
    cell: ({ row }) => {
      const securityKey = row.original
      // Placeholder for navigation or modal opening
      const handleViewDetails = () => {
        console.log("View details for key:", securityKey.id);
        // router.push(`/dashboard/security-keys/${securityKey.id}`); // Example navigation
      };

      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0">
              <span className="sr-only">Open menu</span>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {/* <DropdownMenuLabel>Actions</DropdownMenuLabel> Removed Actions label */}
            {/* Removed Copy Key ID */}
            {/* <DropdownMenuSeparator /> Removed separator as only one item left for now */}
            <DropdownMenuItem onClick={handleViewDetails}>View Details</DropdownMenuItem>
            {/* Removed Revoke Key functionality */}
          </DropdownMenuContent>
        </DropdownMenu>
      )
    },
  },
]