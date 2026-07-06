"use client";

import { useEffect, useState, useMemo } from "react";
import { toast } from "sonner";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { ChevronDown, FileUp } from "lucide-react";
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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { InfoIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { API_URL } from "@/app/utils/constants";
import { useAuthStore } from "@/store/auth";


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
  getFilteredRowModel: () => {
    rows: {
      original: AuditLog;
    }[];
  };
}

export default function AuditLogsPage() {
  const { user: authUser, _hasHydrated } = useAuthStore();
  const authToken = authUser?.authToken ?? null;
  const [data, setData] = useState<AuditLog[]>([]);
  const [pageCount, setPageCount] = useState(0);
  const [loading, setLoading] = useState(true);
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
  const [actionOptions, setActionOptions] = useState<{ value: string; label: string }[]>([{ value: "all", label: "All Actions" }]);
  const [exporting, setExporting] = useState<"excel" | "pdf" | false>(false);
  const [table, setTable] = useState<TableInstance | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLog | null>(null);

  const filteredLogs = useMemo(() => {
    return data.filter(log => {
      if (actionFilterValue !== "all" && log.action_type !== actionFilterValue) {
        return false;
      }
      const searchTerm = globalFilter.toLowerCase();
      return (
        !searchTerm ||
        log.action_type.toLowerCase().includes(searchTerm) ||
        (log.performed_by_username || '').toLowerCase().includes(searchTerm) ||
        log.timestamp.toLowerCase().includes(searchTerm) ||
        (log.details && log.details.toLowerCase().includes(searchTerm))
      );
    });
  }, [data, actionFilterValue, globalFilter]);

  const handleTableInit = (tableInstance: TableInstance) => {
    if (!tableInstance) return;
    setTable(tableInstance);
  };

  useEffect(() => {
    if (!_hasHydrated) return;
    if (!authToken) return;
    fetch(`${API_URL}/system-audit-logs/action-types`, {
      headers: { Authorization: `Bearer ${authToken}` },
    })
      .then((r) => r.json())
      .then((d) => {
        if (d.action_types) {
          setActionOptions([
            { value: "all", label: "All Actions" },
            ...d.action_types.map((t: string) => ({
              value: t,
              label: t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
            })),
          ]);
        }
      })
      .catch(() => {});
  }, [authToken, _hasHydrated]);

  useEffect(() => {
    const fetchAuditLogs = async () => {
      if (!_hasHydrated) return;
      setLoading(true);
      try {
        if (!authToken) return;

        const response = await fetch(
          `${API_URL}/system-audit-logs?page=${pagination.pageIndex + 1}&per_page=${pagination.pageSize}`,
          { headers: { Authorization: `Bearer ${authToken}` } },
        );

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || `Failed to fetch audit logs: ${response.statusText}`);
        }

        const result = await response.json();
        setData(result.logs || []);
        setPageCount(result.pages || 0);
      } catch (err: any) {
        toast.error(err.message || "Failed to load audit logs.");
      } finally {
        setLoading(false);
      }
    };

    fetchAuditLogs();
  }, [pagination, _hasHydrated]);

  // Function to escape CSV values
  const escapeCsvValue = (value: any): string => {
    if (value === null || value === undefined) return '';
    const stringValue = String(value);
    if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
      return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
  };

  // Function to format date for CSV
  const formatDateForCsv = (isoDate: string): string => {
    try {
      const date = new Date(isoDate);
      return date.toLocaleString();
    } catch (e) {
      return isoDate;
    }
  };

  // Function to handle row clicks
  const handleRowClick = (auditLog: AuditLog) => {
    setSelectedAuditLog(auditLog);
    setShowDetailsModal(true);
  };

  // Function to convert a font file to base64
  const loadFont = async (path: string) => {
    const response = await fetch(path);
    const blob = await response.blob();
    return new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64data = reader.result as string;
        resolve(base64data.substring(base64data.indexOf(',') + 1));
      };
      reader.readAsDataURL(blob);
    });
  };

  // Function to export audit logs as PDF
  const exportToPdf = async () => {
    try {
      if (!table || data.length === 0) return;

      // Get filtered data
      const filteredData = table.getFilteredRowModel().rows.map((row) => row.original);

      if (filteredData.length === 0) return;

      // Create PDF document
      const doc = new jsPDF();

      // Load and add regular font
      const regularFont = await loadFont('/assets/fonts/Montserrat-Regular.ttf');
      doc.addFileToVFS('Montserrat-Regular.ttf', regularFont);
      doc.addFont('Montserrat-Regular.ttf', 'MontserratRegular', 'normal');

      // Load and add bold font
      const boldFont = await loadFont('/assets/fonts/Montserrat-Bold.ttf');
      doc.addFileToVFS('Montserrat-Bold.ttf', boldFont);
      doc.addFont('Montserrat-Bold.ttf', 'MontserratBold', 'normal');
      
      // Add title
      doc.setFontSize(16);
      doc.setFont("MontserratBold");
      doc.text("Argus AI Audit Logs Report", 14, 15);
      
      // Switch back to regular font for other text
      doc.setFont("MontserratRegular");
      doc.setFontSize(10);
      doc.text(`Generated on ${new Date().toLocaleString()}`, 14, 25);

      // Add stats summary with filtered counts
      doc.setFont("MontserratBold");
      doc.text("Summary", 14, 35);
      doc.setFont("MontserratRegular");
      doc.text(`Total Filtered Logs: ${filteredData.length}`, 14, 45);

      // Prepare table data
      const tableData = filteredData.map((log: AuditLog) => [
        log.id,
        log.action_type,
        log.performed_by_username,
        log.details,
        formatDateForCsv(log.timestamp),
        log.status,
      ]);

      // Add table
      autoTable(doc, {
        head: [["ID", "Action Type", "Performed By", "Details", "Timestamp", "Status"]],
        body: tableData,
        startY: 55, // Increased spacing from the top content
        theme: 'grid', // Add gridlines
        styles: {
          fontSize: 8,
          cellPadding: 3,
          lineWidth: 0.1, // Border width
          lineColor: [0, 0, 0], // Border color
          font: 'MontserratRegular',
          textColor: [50, 50, 50] // Dark gray text
        },
        headStyles: {
          fillColor: [41, 128, 185],
          textColor: [255, 255, 255],
          font: 'MontserratBold',
          fontStyle: 'bold',
          lineWidth: 0.1,
          halign: 'center'
        },
        alternateRowStyles: {
          fillColor: [245, 245, 245]
        },
        margin: { top: 10 },
        columnStyles: {
          0: { cellWidth: 12 }, // ID
          1: { cellWidth: 40 }, // Action Type
          2: { cellWidth: 25 }, // Performed By
          3: { cellWidth: 45 }, // Details
          4: { cellWidth: 25 }, // Timestamp
          5: { cellWidth: 20 }, // Status
        },
      } as any);

      // Save the PDF
      doc.save(`Argus-AI-Audit-Logs-${new Date().toISOString().slice(0, 10)}.pdf`);

    } catch (error) {
      console.error('Error exporting PDF:', error);
    }
  };

  // Function to export audit logs as CSV
  const exportAuditLogs = async () => {
    try {
      if (!table || data.length === 0) return;

      // Get filtered data
      const filteredData = table.getFilteredRowModel().rows.map((row) => row.original);
      
      if (filteredData.length === 0) return;

      const headers = ["ID", "Action Type", "Performed By", "Details", "Timestamp", "Status"];
      const csvData = filteredData.map((log: AuditLog) => [
        log.id,
        log.action_type,
        log.performed_by_username,
        log.details,
        formatDateForCsv(log.timestamp),
        log.status,
      ]);

      const csvContent = [
        headers.join(","),
        ...csvData.map(row => row.map(escapeCsvValue).join(","))
      ].join("\n");

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", `Argus-AI-Audit-Logs-${new Date().toISOString().slice(0, 10)}.csv`);
      link.style.visibility = "hidden";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url); // Clean up the URL object
    } catch (error) {
      console.error('Error exporting audit logs:', error);
    }
  };

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">System Audit Logs</h2>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                disabled={data.length === 0 || loading}
                className="gap-2"
              >
                <FileUp className="h-4 w-4" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-[150px]">
              <DropdownMenuCheckboxItem
                onClick={async () => {
                  setExporting("excel");
                  await exportAuditLogs();
                  setExporting(false);
                }}
              >
                {exporting === "excel" ? "Exporting..." : "Excel"}
              </DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                onClick={async () => {
                  setExporting("pdf");
                  await exportToPdf();
                  setExporting(false);
                }}
              >
                {exporting === "pdf" ? "Exporting..." : "PDF"}
              </DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>
      </div>
      <div className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Audit Log History</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
                <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
                <span>Loading audit logs...</span>
              </div>
            ) : (
              <DataTable
                columns={columns}
                data={filteredLogs}
              pageCount={pageCount} // Pass pageCount to DataTable
              onTableInit={handleTableInit}
              onRowClick={handleRowClick}
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
                      className="max-w-sm bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                    />
                    <Select
                      value={actionFilterValue}
                      onValueChange={(value) => {
                        setActionFilterValue(value);
                        setPagination((p) => ({ ...p, pageIndex: 0 }));
                      }}
                    >
                      <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
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
                      <Button variant="outline" className="ml-auto bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-3xl text-foreground hover:bg-transparent">
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

      {/* Audit Log Details Modal */}
      <Dialog open={showDetailsModal} onOpenChange={setShowDetailsModal}>
        <DialogContent className="sm:max-w-[600px] font-montserrat">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <InfoIcon className="h-4 w-4" />
              Audit Log Details
            </DialogTitle>
            <DialogDescription>
              Detailed information for log #{selectedAuditLog?.id}
            </DialogDescription>
          </DialogHeader>
          
          {selectedAuditLog && (
            <div className="space-y-4">
              {/* Basic Info Section */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Action Type</p>
                  <Badge variant="outline" className="mt-1">
                    {selectedAuditLog.action_type}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Status</p>
                  <Badge 
                    variant="outline" 
                    className={`mt-1 ${
                      selectedAuditLog.status === 'SUCCESS'
                        ? 'text-green-700 dark:text-green-400 border-green-300 dark:border-green-700'
                        : selectedAuditLog.status === 'FAILURE'
                        ? 'text-red-700 dark:text-red-400 border-red-300 dark:border-red-700'
                        : 'text-gray-700 dark:text-gray-400 border-gray-300 dark:border-gray-700'
                    }`}
                  >
                    {selectedAuditLog.status}
                  </Badge>
                </div>
              </div>

              {/* Timestamp */}
              <div>
                <p className="text-sm font-medium text-muted-foreground">Timestamp</p>
                <div className="mt-1 text-sm">
                  <p className="font-medium">
                    {new Date(selectedAuditLog.timestamp).toLocaleDateString('en-US', {
                      weekday: 'long',
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric'
                    })}
                  </p>
                  <p className="text-muted-foreground">
                    {new Date(selectedAuditLog.timestamp).toLocaleTimeString('en-US', {
                      hour: 'numeric',
                      minute: '2-digit',
                      second: '2-digit',
                      hour12: true
                    })}
                  </p>
                </div>
              </div>

              {/* User Information */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Performed By</p>
                  <div className="mt-1 p-2 bg-muted/50 rounded">
                    <p className="text-sm font-medium">
                      {selectedAuditLog.performed_by_username || "System"}
                    </p>
                    {selectedAuditLog.performed_by_user_id && (
                      <p className="text-xs text-muted-foreground">
                        ID: {selectedAuditLog.performed_by_user_id}
                      </p>
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Affected User</p>
                  <div className="mt-1 p-2 bg-muted/50 rounded">
                    <p className="text-sm font-medium">
                      {selectedAuditLog.user_username || "N/A"}
                    </p>
                    {selectedAuditLog.user_id && (
                      <p className="text-xs text-muted-foreground">
                        ID: {selectedAuditLog.user_id}
                      </p>
                    )}
                  </div>
                </div>
              </div>

              {/* Details */}
              {selectedAuditLog.details && (
                <div>
                  <p className="text-sm font-medium text-muted-foreground">Details</p>
                  <div className="mt-1 p-3 bg-muted/50 rounded text-sm">
                    {selectedAuditLog.details}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}