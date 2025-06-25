"use client";

import { useEffect, useState, useMemo } from "react";
import { ChevronDown, Loader2 } from "lucide-react"; // Import Loader2
import {
  ColumnFiltersState,
  SortingState,
  VisibilityState,
} from "@tanstack/react-table";
import { DataTable } from "@/components/data-table/data-table";
import { AuditLog, columns } from "@/components/data-table/audit-log-columns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { API_URL } from "@/app/utils/constants";

// Action type options for filtering - This will be a more comprehensive list
const actionOptions = [
  { value: "all", label: "All Actions" },
  // User Actions
  { value: "USER_LOGIN_FAILURE", label: "User Login Failure" },
  { value: "USER_LOGIN_SUCCESS", label: "User Login Success" },
  { value: "USER_LOGIN_PASSWORD_VERIFIED", label: "User Login Password Verified" },
  { value: "USER_REGISTER_FAILURE", label: "User Register Failure" },
  { value: "USER_REGISTER_SUCCESS", label: "User Register Success" },
  { value: "USER_UPDATE_FAILURE", label: "User Update Failure" },
  { value: "USER_UPDATE_SUCCESS", label: "User Update Success" },
  { value: "USER_ROLE_UPDATE_FAILURE", label: "Role Update Failure" },
  { value: "USER_ROLE_UPDATE_SUCCESS", label: "Role Update Success" },
  { value: "USER_DELETE_FAILURE", label: "User Delete Failure" },
  { value: "USER_DELETE_SUCCESS", label: "User Delete Success" },
  { value: "USER_ACCOUNT_UNLOCK_FAILURE", label: "User Account Unlock Failure" },
  { value: "USER_ACCOUNT_UNLOCK_SUCCESS", label: "User Account Unlock Success" },

  // WebAuthn Actions
  { value: "SECURITY_KEY_REGISTER_BEGIN_FAILURE", label: "Security Key Register Begin Failure" },
  { value: "SECURITY_KEY_REGISTER_BEGIN_SUCCESS", label: "Security Key Register Begin Success" },
  { value: "SECURITY_KEY_REGISTER_COMPLETE_FAILURE", label: "Security Key Register Complete Failure" },
  { value: "SECURITY_KEY_INITIAL_REGISTER_SUCCESS", label: "Security Key Initial Register Success" },
  { value: "SECURITY_KEY_RE_REGISTER_SUCCESS", label: "Security Key Re-Register Success" },
  { value: "SECURITY_KEY_LOGIN_BEGIN_FAILURE", label: "Security Key Login Begin Failure" },
  { value: "SECURITY_KEY_LOGIN_BEGIN_SUCCESS", label: "Security Key Login Begin Success" },
  { value: "SECURITY_KEY_LOGIN_COMPLETE_FAILURE", label: "Security Key Login Complete Failure" },
  { value: "SECURITY_KEY_DIRECT_LOGIN_SUCCESS", label: "Security Key Direct Login Success" },
  { value: "SECURITY_KEY_2FA_LOGIN_SUCCESS", label: "Security Key 2FA Login Success" },
  { value: "SECURITY_KEY_LOGIN_COMPLETE_ERROR", label: "Security Key Login Complete Error" },
  // Security Key Actions
  { value: "SECURITY_KEY_DELETE_FAILURE", label: "Security Key Delete Failure" },
  { value: "SECURITY_KEY_DELETE_SUCCESS", label: "Security Key Delete Success" },
  { value: "SECURITY_KEY_STATUS_CHANGE_FAILURE", label: "Security Key Status Change Failure" },
  { value: "SECURITY_KEY_ACTIVATE_FAILURE", label: "Security Key Activate Failure" },
  { value: "SECURITY_KEY_ACTIVATE_SUCCESS", label: "Security Key Activate Success" },
  { value: "SECURITY_KEY_DEACTIVATE_SUCCESS", label: "Security Key Deactivate Success" },
  { value: "SECURITY_KEY_UPDATE_FAILURE", label: "Security Key Update Failure" },
  { value: "SECURITY_KEY_UPDATE_SUCCESS", label: "Security Key Update Success" },
  { value: "SECURITY_KEY_RESET_FAILURE", label: "Security Key Reset Failure" },
  { value: "SECURITY_KEY_RESET_SUCCESS", label: "Security Key Reset Success" },
  { value: "SECURITY_KEY_REASSIGN_FAILURE", label: "Security Key Reassign Failure" },
  { value: "SECURITY_KEY_REASSIGN_SUCCESS", label: "Security Key Reassign Success" },
  // System Actions
  { value: "DATABASE_RESET_SUCCESS", label: "DB Reset Success" },
  { value: "DATABASE_RESET_FAILURE", label: "DB Reset Failure" },
];

interface TableInstance {
  getColumn: (id: string) => {
    setFilterValue: (value: string | undefined) => void;
  } | undefined;
  getAllColumns: () => {
    id: string;
    getCanHide: () => boolean;
    getIsVisible: () => boolean;
    toggleVisibility: (value: boolean) => void;
  }[];
}

export default function AuditLogsPage() {
  const [data, setData] = useState<AuditLog[]>([]);
  const [pageCount, setPageCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [globalFilter, setGlobalFilter] = useState("");
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [rowSelection, setRowSelection] = useState({});
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  });
  const [actionFilterValue, setActionFilterValue] = useState<string>("all");

  const filteredLogs = useMemo(() => {
    return data.filter(log => {
      if (actionFilterValue !== "all" && log.action_type !== actionFilterValue) {
        return false;
      }
      const searchTerm = globalFilter.toLowerCase();
      return (
        log.action_type.toLowerCase().includes(searchTerm) ||
        (log.performed_by_username || '').toLowerCase().includes(searchTerm) ||
        log.timestamp.toLowerCase().includes(searchTerm) ||
        (log.details && log.details.toLowerCase().includes(searchTerm))
      );
    });
  }, [data, actionFilterValue, globalFilter]);

  const paginatedLogs = useMemo(() => {
    const start = pagination.pageIndex * pagination.pageSize;
    const end = start + pagination.pageSize;
    return filteredLogs.slice(start, end);
  }, [filteredLogs, pagination]);

  useEffect(() => {
    if (filteredLogs.length > 0) {
      setPageCount(Math.ceil(filteredLogs.length / pagination.pageSize));
    }
  }, [filteredLogs, pagination.pageSize]);

  useEffect(() => {
    const fetchAuditLogs = async () => {
      setLoading(true);
      setError(null);
      try {
        const userStr = sessionStorage.getItem('user');
        if (!userStr) {
          throw new Error('User not authenticated. Session storage empty.');
        }
        
        interface UserData {
          authToken: string;
        }
        
        const user = JSON.parse(userStr) as UserData;
        const authToken = user.authToken;

        if (!authToken) {
          setError("Authentication token not found in session storage.");
          setLoading(false);
          return;
        }

        const response = await fetch(`${API_URL}/system-audit-logs`, {
          headers: {
            Authorization: `Bearer ${authToken}`,
          },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || `Failed to fetch audit logs: ${response.statusText}`);
        }

        const result = await response.json();
        setData(result.logs || []);
      } catch (err) {
        let errorMessage = "An unknown error occurred.";
        if (err instanceof Error) {
          errorMessage = err.message;
        }
        if (typeof err === 'object' && err !== null && 'status' in err && typeof err.status === 'number') {
          errorMessage += ` (Status: ${err.status})`;
        } else if (typeof err === 'object' && err !== null && 'message' in err && typeof err.message === 'string' && err.message.includes('Failed to fetch')) {
           errorMessage = `Network error or CORS issue: Failed to fetch. Check browser console and network tab for details.`;
        }
        setError(errorMessage);
        console.error("Error fetching audit logs:", err, errorMessage);
      } finally {
        setLoading(false);
      }
    };

    fetchAuditLogs();
  }, []);

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
            {loading ? (
              <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8"> {/* Adjusted to match users page */}
                <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div> {/* Spinner div */}
                <span>Loading audit logs...</span> {/* Text */}
              </div>
            ) : error ? (
              <div className="flex items-center justify-center py-10">
                <p className="text-red-500">{error}</p>
              </div>
            ) : (
              <DataTable
                columns={columns}
                data={paginatedLogs}
              pageCount={pageCount} // Pass pageCount to DataTable
              state={{
                sorting,
                columnFilters,
                columnVisibility,
                rowSelection,
                pagination,
                globalFilter, // Pass globalFilter to DataTable state
              }}
              onSortingChange={setSorting}
              onColumnFiltersChange={setColumnFilters}
              onColumnVisibilityChange={setColumnVisibility}
              onRowSelectionChange={setRowSelection}
              onPaginationChange={setPagination}
              enableRowSelection={true}
              getPaginationRowModel={true}
              getSortedRowModel={true}
              getFilteredRowModel={true}
              toolbar={(table) => (
                <div className="flex items-center justify-between w-full font-montserrat">
                  <div className="flex items-center space-x-4">
                    <Input
                      placeholder="Search all fields..."
                      value={globalFilter ?? ""}
                      onChange={(event) => setGlobalFilter(event.target.value)}
                      className="max-w-sm dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                    />
                    <Select
                      value={actionFilterValue}
                      onValueChange={(value) => {
                        setActionFilterValue(value);
                        // This will trigger the useEffect to refetch data with the new action_type filter
                        // Client-side filtering for 'action_type' column can also be set if preferred:
                        // const column = table?.getColumn("action_type");
                        // if (column) {
                        //   column.setFilterValue(value === "all" ? undefined : value);
                        // }
                      }}
                    >
                      <SelectTrigger className="w-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                        <SelectValue placeholder="Filter by action" />
                      </SelectTrigger>
                      <SelectContent>
                        {actionOptions.map(option => (
                          <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" className="dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                        Columns <ChevronDown className="ml-2 h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="rounded-xl">
                      {table
                        ?.getAllColumns()
                        .filter((column) => column.getCanHide())
                        .map((column) => (
                          <DropdownMenuCheckboxItem
                            key={column.id}
                            className="capitalize"
                            checked={column.getIsVisible()}
                            onCheckedChange={(value) =>
                              column.toggleVisibility(!!value)
                            }
                          >
                            {column.id}
                          </DropdownMenuCheckboxItem>
                        ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              )}
            />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}