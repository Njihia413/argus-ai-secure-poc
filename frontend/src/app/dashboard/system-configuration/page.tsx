"use client"

import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { toast } from 'sonner';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import { useStore } from '@/app/utils/store';
import { API_URL } from '@/app/utils/constants';
import { DataTable } from '@/components/data-table/data-table';
import { columns as logColumns, AuditLog } from '@/components/data-table/audit-log-columns';
import { SortingState, ColumnFiltersState, VisibilityState, PaginationState } from '@tanstack/react-table';

interface SystemConfigurationResponse {
  maintenance_mode: boolean;
  maintenance_message: string | null;
  updated_by: string | null;
  updated_at: string | null;
}

interface UpdateSystemConfigurationResponse {
  message: string;
  maintenance_mode: boolean;
}

export default function SystemConfigurationPage() {
  const [maintenanceMode, setMaintenanceMode] = useState(false);
  const [maintenanceMessage, setMaintenanceMessage] = useState('');
  const [currentMessage, setCurrentMessage] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [updatedBy, setUpdatedBy] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [pageCount, setPageCount] = useState(0);
  const [isLogsLoading, setIsLogsLoading] = useState(true);
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: 10,
  });
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});

  const fetchConfiguration = useCallback(async () => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    const authToken = userInfo.authToken;
    if (!authToken) {
      toast.error("Authentication token not found.");
      setIsLoading(false);
      return;
    }
    try {
      const response = await axios.get<SystemConfigurationResponse>(`${API_URL}/system-configuration`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      setMaintenanceMode(response.data.maintenance_mode);
      setCurrentMessage(response.data.maintenance_message || '');
      setUpdatedBy(response.data.updated_by);
      setUpdatedAt(response.data.updated_at);
    } catch (error) {
      toast.error('Failed to fetch system configuration.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const fetchLogs = useCallback(async () => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    const authToken = userInfo.authToken;
    if (!authToken) {
      setIsLogsLoading(false);
      return;
    }
    setIsLogsLoading(true);
    try {
      const response = await axios.get<{ logs: AuditLog[], pages: number }>(`${API_URL}/system-audit-logs`, {
        headers: { Authorization: `Bearer ${authToken}` },
        params: {
          page: pagination.pageIndex + 1,
          per_page: pagination.pageSize,
          action_type: 'MAINTENANCE_MODE_UPDATE', // Filter for maintenance mode events
        },
      });
      setLogs(response.data.logs);
      setPageCount(response.data.pages);
    } catch (error) {
      toast.error('Failed to fetch system configuration logs.');
    } finally {
      setIsLogsLoading(false);
    }
  }, [pagination]);

  useEffect(() => {
    fetchConfiguration();
    fetchLogs();
  }, [fetchConfiguration, fetchLogs]);

  const handleToggleMaintenanceMode = async () => {
    if (!maintenanceMode && !maintenanceMessage) {
      toast.error('A message is required to enable maintenance mode.');
      return;
    }

    setIsLoading(true);
    try {
      const response = await axios.post<UpdateSystemConfigurationResponse>(
        `${API_URL}/system-configuration`,
        {
          maintenance_mode: !maintenanceMode,
          maintenance_message: maintenanceMessage,
        },
        { headers: { Authorization: `Bearer ${JSON.parse(sessionStorage.getItem("user") || "{}").authToken}` } }
      );
      toast.success(response.data.message);
      await fetchConfiguration();
      await fetchLogs();
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'An unexpected error occurred.';
      toast.error(`Failed to update system configuration: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
        <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
            <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
            <span>Loading system configuration...</span>
        </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">System Configuration</h1>
      <Card>
        <CardHeader>
          <CardTitle>Maintenance Mode</CardTitle>
          <CardDescription>
            Enable maintenance mode to temporarily disable access to the system for non-admin users.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert variant={maintenanceMode ? 'destructive' : 'default'} className={`border-2 ${maintenanceMode ? 'border-red-500' : 'border-green-500'}`}>
            {maintenanceMode ? <ShieldAlert className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
            <AlertTitle>{maintenanceMode ? 'System is in Maintenance Mode' : 'System is Operational'}</AlertTitle>
            <AlertDescription>
              {maintenanceMode
                ? `The system was put into maintenance mode by ${updatedBy || 'an admin'} at ${new Date(updatedAt!).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} ${new Date(updatedAt!).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true })}. The following message is displayed to users: "${currentMessage}"`
                : 'The system is fully operational.'}
            </AlertDescription>
          </Alert>

          <div className={`flex items-center space-x-4 rounded-md border-2 p-4 ${maintenanceMode ? 'border-red-500' : 'border-green-500'}`}>
            <div className="flex-1 space-y-1">
              <p className="text-sm font-medium leading-none">
                {maintenanceMode ? 'Disable Maintenance Mode' : 'Enable Maintenance Mode'}
              </p>
              <p className="text-sm text-muted-foreground">
                {maintenanceMode
                  ? 'This will restore full access to all users.'
                  : 'This will prevent non-admin users from logging in.'}
              </p>
            </div>
            <Switch
              checked={maintenanceMode}
              onCheckedChange={handleToggleMaintenanceMode}
              disabled={isLoading}
              aria-readonly
            />
          </div>
          
          {!maintenanceMode && (
            <div className="space-y-2">
              <label htmlFor="maintenanceMessage" className="text-sm font-medium">
                Maintenance Message
              </label>
              <Textarea
                id="maintenanceMessage"
                placeholder="Enter a message to display to users during maintenance (e.g., 'The system is currently undergoing scheduled maintenance.')."
                value={maintenanceMessage}
                onChange={(e) => setMaintenanceMessage(e.target.value)}
                className="min-h-[100px]"
              />
              <Button onClick={handleToggleMaintenanceMode} disabled={isLoading || !maintenanceMessage}>
                Enable Maintenance Mode
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Configuration History</CardTitle>
          <CardDescription>
            An audit trail of all system configuration changes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLogsLoading ? (
            <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
              <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
              <span>Loading logs...</span>
            </div>
          ) : (
            <DataTable
              columns={logColumns.filter(column => {
                const key = 'accessorKey' in column ? column.accessorKey : column.id;
                return key !== 'user_username' && key !== 'target_entity_id';
              })}
              data={logs}
              pageCount={pageCount}
              state={{
                sorting,
                columnFilters,
                columnVisibility,
                pagination,
              }}
              onSortingChange={setSorting}
              onColumnFiltersChange={setColumnFilters}
              onColumnVisibilityChange={setColumnVisibility}
              onPaginationChange={setPagination}
              manualPagination={true}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
