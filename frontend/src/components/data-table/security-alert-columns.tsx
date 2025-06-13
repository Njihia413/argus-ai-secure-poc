"use client"

import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { cn } from "@/lib/utils"
import {
  AlertTriangle,
  Shield,
  Clock,
  MapPin,
  Laptop,
  UserX,
  User,
  Lock,
  Globe,
  AlertCircle,
  ArrowDownUp,
} from "lucide-react"

// Type definition from security page
export type SecurityAlert = {
  id: number
  type: string
  user: string
  details: string
  time: string
  severity: "High" | "Medium" | "Low"
  resolved: boolean
}

export const columns: ColumnDef<SecurityAlert>[] = [
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
      <div className="py-2">
        <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(value) => row.toggleSelected(!!value)}
        aria-label="Select row"
        />
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
  },
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }) => {
      const alert = row.original

      // Select the appropriate icon based on the alert type
      const getAlertIcon = (type: string) => {
        switch(type) {
          case "Failed Login":
            return <UserX className="h-4 w-4 mr-2 text-red-500" />
          case "New IP Address":
            return <Globe className="h-4 w-4 mr-2 text-blue-500" />
          case "Suspicious IP":
            return <AlertTriangle className="h-4 w-4 mr-2 text-red-500" />
          case "Account Lockout":
            return <Lock className="h-4 w-4 mr-2 text-red-500" />
          case "New Device":
            return <Laptop className="h-4 w-4 mr-2 text-blue-500" />
          case "Unusual Time":
            return <Clock className="h-4 w-4 mr-2 text-amber-500" />
          case "Location Change":
            return <MapPin className="h-4 w-4 mr-2 text-amber-500" />
          case "Rapid Travel":
            return <ArrowDownUp className="h-4 w-4 mr-2 text-red-500" />
          case "High Risk Login":
            return <AlertCircle className="h-4 w-4 mr-2 text-red-500" />
          case "Moderate Risk Login":
            return <AlertCircle className="h-4 w-4 mr-2 text-amber-500" />
          case "Admin Account Login":
            return <User className="h-4 w-4 mr-2 text-blue-500" />
          default:
            return <Shield className="h-4 w-4 mr-2 text-gray-500" />
        }
      }

      return (
        <div className="flex items-center py-2">
          {getAlertIcon(alert.type)}
          {alert.type}
        </div>
      )
    }
  },
  {
    accessorKey: "user",
    header: "User",
    cell: ({ row }) => (
      <div className="py-2">
        {row.getValue("user")}
      </div>
    )
  },
  {
    accessorKey: "details",
    header: "Details",
    cell: ({ row }) => (
      <div className="py-2">
        {row.getValue("details")}
      </div>
    )
  },
  {
    accessorKey: "time",
    header: "Time",
    cell: ({ row }) => {
      const isoTime = row.getValue<string>("time");
      try {
        const date = new Date(isoTime);
        return (
          <div className="py-2">
            {date.toLocaleString()}
          </div>
        );
      } catch (e) {
        return isoTime;
      }
    }
  },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ row }) => {
      const alert = row.original
      return (
        <div className="py-2">
        <Badge
          variant="outline"
          className={
            alert.severity === "High"
              ? "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700"
              : alert.severity === "Medium"
                ? "text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700"
                : "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700"
          }
        >
          {alert.severity}
        </Badge>
        </div>
      )
    }
  }
]