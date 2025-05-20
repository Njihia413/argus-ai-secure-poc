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
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<AuditLog[]>([]);

  useEffect(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");

    if (!userInfo || !userInfo.authToken) {
      toast.error("You need to log in");
      return;
    }

    const fetchData = async () => {
      try {
        const response = await axios.get<AuditLogsResponse>(
          `${API_URL}/security-keys/audit-logs`,
          {
            headers: {
              Authorization: `Bearer ${userInfo.authToken}`,
            },
          }
        );

        if (response.data && response.data.logs) {
          setData(response.data.logs);
        }
      } catch (error: any) {
        console.error("Error fetching audit logs:", error);
        toast.error(error.response?.data?.error || "Failed to fetch audit logs");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
        <Skeleton className="h-8 w-[300px] mb-4" />
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-[200px]" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[400px] w-full" />
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">Security Key Audit Logs</h2>
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