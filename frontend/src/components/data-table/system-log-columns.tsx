"use client";

import { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "@/components/ui/badge"; // Assuming Badge might be used for actions

// Define the shape of a SystemLog object based on backend response
// This should align with the serialization in get_system_audit_logs in app.py
export type SystemLog = {
  id: number;
  timestamp: string; // ISO string
  action: string;
  details: Record<string, any> | string | null; // Can be JSON object or string
  performed_by_user: {
    id: number;
    username: string;
    firstName: string;
    lastName: string;
  } | null;
  target_user: {
    id: number;
    username: string;
    firstName: string;
    lastName: string;
  } | null;
  target_key: {
    id: number;
    model: string | null;
    serialNumber: string | null;
  } | null;
};

export const columns: ColumnDef<SystemLog>[] = [
  {
    accessorKey: "timestamp",
    header: "Timestamp",
    cell: ({ row }) => {
      const timestamp = row.getValue("timestamp");
      return timestamp ? format(new Date(timestamp as string), "MMM dd, yyyy HH:mm:ss") : "N/A";
    },
  },
  {
    accessorKey: "action",
    header: "Action",
    cell: ({ row }) => {
      const action = row.getValue("action") as string;
      // Basic badge for now, can be enhanced with colors per action type later
      return <Badge variant="outline" className="capitalize">{action.replace(/_/g, " ").toLowerCase()}</Badge>;
    }
  },
  {
    accessorKey: "performed_by_user",
    header: "Performed By",
    cell: ({ row }) => {
      const performedBy = row.getValue("performed_by_user") as SystemLog["performed_by_user"];
      return performedBy ? `${performedBy.firstName} ${performedBy.lastName} (${performedBy.username})` : "System";
    },
    // Enable filtering for this column if needed in AuditDataTable
    // filterFn: (row, columnId, filterValue) => { ... } 
  },
  {
    accessorKey: "target_user",
    header: "Target User",
    cell: ({ row }) => {
      const targetUser = row.getValue("target_user") as SystemLog["target_user"];
      return targetUser ? `${targetUser.firstName} ${targetUser.lastName} (${targetUser.username})` : "N/A";
    },
  },
  {
    accessorKey: "target_key_id", // Displaying ID for now, could be model/serial if preferred
    header: "Target Key ID",
    cell: ({ row }) => {
      const targetKey = row.getValue("target_key") as SystemLog["target_key"];
      return targetKey ? targetKey.id : "N/A";
    },
  },
  {
    accessorKey: "details",
    header: "Details",
    cell: ({ row }) => {
      const details = row.getValue("details");
      if (typeof details === 'object' && details !== null) {
        return <pre className="text-xs whitespace-pre-wrap">{JSON.stringify(details, null, 2)}</pre>;
      }
      return <span className="text-xs">{details as string || "N/A"}</span>;
    },
  },
];