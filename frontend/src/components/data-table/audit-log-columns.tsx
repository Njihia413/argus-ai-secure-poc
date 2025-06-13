"use client";

import { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "../ui/badge";
import { Checkbox } from "@/components/ui/checkbox";

export type AuditLog = {
  id: string;
  securityKeyId: string;
  userId: string;
  username: string;
  action: string;
  details: string;
  timestamp: string;
  performedBy: {
    id: string;
    username: string;
  };
  previousState?: any;
  newState?: any;
};

export const columns: ColumnDef<AuditLog>[] = [
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
    accessorKey: "action",
    header: "Action",
    cell: ({ row }) => {
      const action = row.getValue("action") as string;
      let textColor = "";
      let borderColor = "";
      
      switch (action.toLowerCase()) {
        case "register":
        case "initial-register": // Adding this case for consistency
        case "re-register": // Adding this case for consistency
          textColor = "text-green-700 dark:text-green-400";
          borderColor = "border-green-300 dark:border-green-700";
          break;
        case "deactivate":
          textColor = "text-red-700 dark:text-red-400";
          borderColor = "border-red-300 dark:border-red-700";
          break;
        case "activate":
          textColor = "text-blue-700 dark:text-blue-400";
          borderColor = "border-blue-300 dark:border-blue-700";
          break;
        case "reassign":
          textColor = "text-yellow-700 dark:text-yellow-400";
          borderColor = "border-yellow-300 dark:border-yellow-700";
          break;
        case "reset":
          textColor = "text-purple-700 dark:text-purple-400";
          borderColor = "border-purple-300 dark:border-purple-700";
          break;
        default:
          textColor = "text-gray-700 dark:text-gray-400";
          borderColor = "border-gray-300 dark:border-gray-700";
      }

      return (
        <div className="py-2">
          <Badge
            variant="outline"
            className={`${textColor} ${borderColor}`}
          >
            {action}
          </Badge>
        </div>
      );
    },
  },
  {
    accessorKey: "details",
    header: "Details",
    cell: ({ row }) => (
      <div className="py-2">
        {row.getValue("details")}
      </div>
    ),
  },
  {
    accessorKey: "timestamp",
    header: "Time",
    cell: ({ row }) => {
      return (
        <div className="py-2">
          {format(new Date(row.getValue("timestamp")), "MMM dd, yyyy HH:mm:ss")}
        </div>
      );
    },
  },
  {
    accessorKey: "performedBy",
    header: "Performed By",
    cell: ({ row }) => {
      const performedBy = row.getValue("performedBy") as { username: string };
      return (
        <div className="py-2">
          {performedBy.username}
        </div>
      );
    },
    // Custom filter function for the "Search..." input
    filterFn: (row, columnId, filterValue) => {
      const performedByUsername = (row.getValue("performedBy") as { username: string })?.username?.toLowerCase() || "system";
      const action = (row.getValue("action") as string)?.toLowerCase();
      const searchTerm = String(filterValue).toLowerCase(); // Ensure filterValue is a string

      return performedByUsername.includes(searchTerm) || action.includes(searchTerm);
    },
  },
];