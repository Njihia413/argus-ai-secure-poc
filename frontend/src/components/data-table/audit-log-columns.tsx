"use client";

import { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "../ui/badge";

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
    accessorKey: "username",
    header: "User",
  },
  {
    accessorKey: "action",
    header: "Action",
    cell: ({ row }) => {
      const action = row.getValue("action") as string;
      let bgColor = "";
      let textColor = "";
      let borderColor = "";
      
      switch (action.toLowerCase()) {
        case "register":
          bgColor = "bg-green-50";
          textColor = "text-green-700";
          borderColor = "border-green-200";
          break;
        case "deactivate":
          bgColor = "bg-red-50";
          textColor = "text-red-700";
          borderColor = "border-red-200";
          break;
        case "activate":
          bgColor = "bg-blue-50";
          textColor = "text-blue-700";
          borderColor = "border-blue-200";
          break;
        case "reassign":
          bgColor = "bg-yellow-50";
          textColor = "text-yellow-700";
          borderColor = "border-yellow-200";
          break;
        case "reset":
          bgColor = "bg-purple-50";
          textColor = "text-purple-700";
          borderColor = "border-purple-200";
          break;
        default:
          bgColor = "bg-gray-50";
          textColor = "text-gray-700";
          borderColor = "border-gray-200";
      }

      return (
        <Badge 
          variant="outline" 
          className={`${bgColor} ${textColor} ${borderColor}`}
        >
          {action}
        </Badge>
      );
    },
  },
  {
    accessorKey: "details",
    header: "Details",
  },
  {
    accessorKey: "timestamp",
    header: "Time",
    cell: ({ row }) => {
      return format(new Date(row.getValue("timestamp")), "MMM dd, yyyy HH:mm:ss");
    },
  },
  {
    accessorKey: "performedBy",
    header: "Performed By",
    cell: ({ row }) => {
      const performedBy = row.getValue("performedBy") as { username: string };
      return performedBy.username;
    },
  },
];