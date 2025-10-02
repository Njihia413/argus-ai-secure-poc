"use client";

import { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "../ui/badge";
import { Checkbox } from "@/components/ui/checkbox";

export type AuditLog = {
  id: number;
  timestamp: string;
  user_id?: number | null;
  user_username?: string | null;
  performed_by_user_id?: number | null;
  performed_by_username?: string | null;
  action_type: string;
  target_entity_type?: string | null;
  details?: string | null;
  status: 'SUCCESS' | 'FAILURE';
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
    accessorKey: "action_type",
    header: "Action Type",
    cell: ({ row }) => {
      const actionType = row.getValue("action_type") as string;
      // Basic styling for now, can be expanded like the old 'action' column
      return (
        <div className="py-2">
          <Badge
            variant="outline"
          >
            {actionType}
          </Badge>
        </div>
      );
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const status = row.getValue("status") as string;
      let textColor = "";
      let borderColor = "";
      if (status === "SUCCESS") {
        textColor = "text-green-700 dark:text-green-400";
        borderColor = "border-green-300 dark:border-green-700";
      } else if (status === "FAILURE") {
        textColor = "text-red-700 dark:text-red-400";
        borderColor = "border-red-300 dark:border-red-700";
      } else {
        textColor = "text-gray-700 dark:text-gray-400";
        borderColor = "border-gray-300 dark:border-gray-700";
      }
      return (
        <div className="py-2">
          <Badge
            variant="outline"
            className={`${textColor} ${borderColor}`}
          >
            {status}
          </Badge>
        </div>
      );
    }
  },
  {
    accessorKey: "details",
    header: "Details",
    cell: ({ row }) => {
      const details = row.getValue("details") as string | null;
      return (
        <div className="py-2 truncate max-w-xs" title={details ?? undefined}>
          {details || "-"}
        </div>
      );
    }
  },
  {
    accessorKey: "user_username",
    header: "Affected User",
    cell: ({ row }) => (
      <div className="py-2">
        {row.getValue("user_username") || "-"}
      </div>
    ),
  },
  {
    accessorKey: "timestamp",
    header: "Time",
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
    accessorKey: "performed_by_username",
    header: "Performed By",
    cell: ({ row }) => {
      const performedByUsername = row.getValue("performed_by_username") as string | null;
      return (
        <div className="py-2">
          {performedByUsername || "System"}
        </div>
      );
    },
    // Custom filter function for the "Search..." input
    // This will be used by the global search input on the audit logs page
    filterFn: (row, columnId, filterValue) => {
      const searchTerm = String(filterValue).toLowerCase();

      const performedBy = (row.getValue("performed_by_username") as string || "system").toLowerCase();
      const affectedUser = (row.getValue("user_username") as string || "").toLowerCase();
      const actionType = (row.getValue("action_type") as string || "").toLowerCase();
      const details = (row.getValue("details") as string || "").toLowerCase();
      const status = (row.getValue("status") as string || "").toLowerCase();


      return performedBy.includes(searchTerm) ||
             affectedUser.includes(searchTerm) ||
             actionType.includes(searchTerm) ||
             details.includes(searchTerm) ||
             status.includes(searchTerm);
    },
  },
];