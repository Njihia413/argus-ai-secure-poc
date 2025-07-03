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

interface EmergencyStatusResponse {
  is_locked_down: boolean;
  lockdown_message: string | null;
  locked_down_by: string | null;
  locked_down_at: string | null;
}

interface ToggleLockdownResponse {
  message: string;
  is_locked_down: boolean;
}

export default function EmergencyActionsPage() {
  const [isLocked, setIsLocked] = useState(false);
  const [lockdownMessage, setLockdownMessage] = useState('');
  const [currentMessage, setCurrentMessage] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [lockedBy, setLockedBy] = useState<string | null>(null);
  const [lockedAt, setLockedAt] = useState<string | null>(null);

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

  const fetchStatus = useCallback(async () => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    const authToken = userInfo.authToken;
    if (!authToken) {
      toast.error("Authentication token not found.");
      setIsLoading(false);
      return;
    }
    try {
      const response = await axios.get<EmergencyStatusResponse>(`${API_URL}/emergency-actions`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      setIsLocked(response.data.is_locked_down);
      setCurrentMessage(response.data.lockdown_message || '');
      setLockedBy(response.data.locked_down_by);
      setLockedAt(response.data.locked_down_at);
    } catch (error) {
      toast.error('Failed to fetch system status.');
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
          action_type: 'SYSTEM_LOCKDOWN_ENABLED,SYSTEM_LOCKDOWN_DISABLED', // Filter for lockdown related events
        },
      });
      setLogs(response.data.logs);
      setPageCount(response.data.pages);
    } catch (error) {
      toast.error('Failed to fetch emergency action logs.');
    } finally {
      setIsLogsLoading(false);
    }
  }, [pagination]);

  useEffect(() => {
    fetchStatus();
    fetchLogs();
  }, [fetchStatus, fetchLogs]);

  const handleToggleLockdown = async () => {
    const action = isLocked ? 'unlock' : 'lock';
    if (action === 'lock' && !lockdownMessage) {
      toast.error('A message is required to lock down the system.');
      return;
    }

    setIsLoading(true);
    try {
      const response = await axios.post<ToggleLockdownResponse>(
        `${API_URL}/emergency/toggle-lockdown`,
        { action, message: lockdownMessage },
        { headers: { Authorization: `Bearer ${JSON.parse(sessionStorage.getItem("user") || "{}").authToken}` } }
      );
      toast.success(response.data.message);
      await fetchStatus(); // Refresh status from backend
      await fetchLogs(); // Refresh logs
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || 'An unexpected error occurred.';
      toast.error(`Failed to ${action} system: ${errorMessage}`);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
        <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
            <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
            <span>Loading system status...</span>
        </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Emergency Actions</h1>
      <Card>
        <CardHeader>
          <CardTitle>System Lockdown</CardTitle>
          <CardDescription>
            In case of a critical security incident, you can lock down the entire system. This will prevent all non-admin users from accessing the application.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert variant={isLocked ? 'destructive' : 'default'} className={`border-2 ${isLocked ? 'border-red-500' : 'border-green-500'}`}>
            {isLocked ? <ShieldAlert className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
            <AlertTitle>{isLocked ? 'System is Locked Down' : 'System is Operational'}</AlertTitle>
            <AlertDescription>
              {isLocked
                ? `The system was locked down by ${lockedBy || 'an admin'} at ${new Date(lockedAt!).toLocaleString()}. The following message is displayed to users: "${currentMessage}"`
                : 'All systems are running normally. No emergency lockdown is in effect.'}
            </AlertDescription>
          </Alert>

          <div className={`flex items-center space-x-4 rounded-md border-2 p-4 ${isLocked ? 'border-red-500' : 'border-green-500'}`}>
            <div className="flex-1 space-y-1">
              <p className="text-sm font-medium leading-none">
                {isLocked ? 'Unlock System' : 'Enable System Lockdown'}
              </p>
              <p className="text-sm text-muted-foreground">
                {isLocked
                  ? 'This will restore full access to all users.'
                  : 'This will immediately restrict access for all non-admin users.'}
              </p>
            </div>
            <Switch
              checked={isLocked}
              onCheckedChange={handleToggleLockdown}
              disabled={isLoading}
              aria-readonly
            />
          </div>

          {!isLocked && (
            <div className="space-y-2">
              <label htmlFor="lockdownMessage" className="text-sm font-medium">
                Lockdown Message
              </label>
              <Textarea
                id="lockdownMessage"
                placeholder="Enter a message to display to users during the lockdown (e.g., 'System is down for emergency maintenance.')."
                value={lockdownMessage}
                onChange={(e) => setLockdownMessage(e.target.value)}
                className="min-h-[100px]"
              />
              <Button onClick={handleToggleLockdown} disabled={isLoading || !lockdownMessage}>
                Lock System
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Lockdown History</CardTitle>
          <CardDescription>
            An audit trail of all system lockdown and unlock actions.
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
              columns={logColumns}
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