"use client";

import { useEffect, useState } from "react";
import { AuditDataTable } from "@/components/data-table/audit-data-table";
import { AuditLog, columns } from "@/components/data-table/audit-log-columns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import axios from "axios";
import { API_URL } from "@/app/utils/constants";

export default function AuditLogsPage() {
  // Data will be fetched by a more general system log component or passed as props
  const [data, setData] = useState<AuditLog[]>([]);

  // Removed useEffect and loading state as data fetching is removed from this page

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">System Audit Logs</h2>
      </div>
      <div className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Audit Log History</CardTitle>
          </CardHeader>
          <CardContent>
            <AuditDataTable columns={columns} data={data} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

interface AuditLogsResponse {
  logs: AuditLog[];
  total: number;
  pages: number;
  currentPage: number;
}