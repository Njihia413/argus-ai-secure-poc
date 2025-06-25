"use client"

import { useEffect, useState } from "react"
import jsPDF from "jspdf"
import autoTable from "jspdf-autotable"
import {
  ColumnFiltersState,
  SortingState,
  VisibilityState,
} from "@tanstack/react-table"
import { Shield, ChevronDown, FileUp } from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { API_URL } from "@/app/utils/constants"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { DataTable } from "@/components/data-table/data-table"
import { Table } from "@tanstack/react-table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Progress } from "@/components/ui/progress"
import { SecurityAlert, columns } from "@/components/data-table/security-alert-columns"

type SecurityStats = {
  alertStats: {
    total: number
    bySeverity: {
      High: number
      Medium: number
      Low: number
    }
  }
  securityScore: {
    current: number
    change: number
  }
  activeSessions: {
    total: number
    byDevice: Record<string, number>
    uniqueDevices: number
  }
}

const emptyStats: SecurityStats = {
  alertStats: {
    total: 0,
    bySeverity: {
      High: 0,
      Medium: 0,
      Low: 0
    }
  },
  securityScore: {
    current: 0,
    change: 0
  },
  activeSessions: {
    total: 0,
    byDevice: {},
    uniqueDevices: 0
  }
}

// Alert type options for filtering with non-empty values
const alertTypeOptions = [
  { label: "All Types", value: "all" }, // Changed from empty string to "all"
  { label: "Failed Login", value: "Failed Login" },
  { label: "New IP Address", value: "New IP Address" },
  { label: "Suspicious IP", value: "Suspicious IP" },
  { label: "Account Lockout", value: "Account Lockout" },
  { label: "New Device", value: "New Device" },
  { label: "Unusual Time", value: "Unusual Time" },
  { label: "Location Change", value: "Location Change" },
  { label: "Rapid Travel", value: "Rapid Travel" },
  { label: "High Risk Login", value: "High Risk Login" },
  { label: "Moderate Risk Login", value: "Moderate Risk Login" },
  { label: "Admin Account Login", value: "Admin Account Login" }
]

const severityOptions = [
  { label: "All Severities", value: "all" },
  { label: "High", value: "High" },
  { label: "Medium", value: "Medium" },
  { label: "Low", value: "Low" },
]

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
      original: SecurityAlert;
    }[];
  };
}

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [stats, setStats] = useState<SecurityStats>(emptyStats)
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState<"excel" | "pdf" | false>(false)
  const [error, setError] = useState<string | null>(null)
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = useState({})
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  })
  const [severityFilterValue, setSeverityFilterValue] = useState<string>("all")
  const [typeFilterValue, setTypeFilterValue] = useState<string>("all")
  const [pageCount, setPageCount] = useState(0)


  // Handle table reference
  const [table, setTable] = useState<TableInstance | null>(null)

  const handleTableInit = (tableInstance: TableInstance) => {
    if (!tableInstance) return;
    setTable(tableInstance)
  }

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true)
        setError(null)

        const userStr = sessionStorage.getItem('user')
        if (!userStr) {
          throw new Error('User not authenticated')
        }
        
        interface UserData {
          authToken: string;
        }
        
        const user = JSON.parse(userStr) as UserData
        const authToken = user.authToken

        // Fetch alerts with pagination
        const queryParams = new URLSearchParams({
          page: (pagination.pageIndex + 1).toString(),
          per_page: pagination.pageSize.toString(),
        })

         if (severityFilterValue && severityFilterValue !== "all") {
          queryParams.append("severity", severityFilterValue);
        }

        if (typeFilterValue && typeFilterValue !== "all") {
          queryParams.append("alert_type", typeFilterValue);
        }


        const alertsRes = await fetch(`${API_URL}/security/alerts?${queryParams.toString()}`, {
          headers: {
            'Authorization': `Bearer ${authToken}`
          }
        })

        if (!alertsRes.ok) {
          const alertsError = await alertsRes.json()
          throw new Error(alertsError.error || 'Failed to fetch alerts')
        }

        interface AlertsResponse {
          alerts: SecurityAlert[];
          total?: number;
          pages: number;
        }
        const alertsData = await alertsRes.json() as AlertsResponse

        // Fetch stats
        const statsRes = await fetch(`${API_URL}/security/stats`, {
          headers: {
            'Authorization': `Bearer ${authToken}`
          }
        })

        if (!statsRes.ok) {
          const statsError = await statsRes.json()
          throw new Error(statsError.error || 'Failed to fetch security stats')
        }

        const statsData = await statsRes.json() as SecurityStats

        setAlerts(alertsData.alerts || [])
        setPageCount(Math.ceil(statsData.alertStats.total / pagination.pageSize))
        setStats(statsData || emptyStats)
      } catch (error) {
        const e = error as Error;
        console.error('Error fetching security data:', error)
        setError(e.message || 'Failed to fetch security data')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [pagination, severityFilterValue, typeFilterValue])

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

  // Function to convert a font file to base64
  const loadFont = async (path: string) => {
    const response = await fetch(path);
    const blob = await response.blob();
    return new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64data = reader.result as string;
        resolve(base64data.substr(base64data.indexOf(',') + 1));
      };
      reader.readAsDataURL(blob);
    });
  };

  // Function to export alerts as PDF
  const exportToPdf = async () => {
    try {
      if (!table || !alerts.length) return;

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
      doc.text("Argus AI Security Alerts Report", 14, 15);
      
      // Switch back to regular font for other text
      doc.setFont("MontserratRegular");
      doc.setFontSize(10);
      doc.text(`Generated on ${new Date().toLocaleString()}`, 14, 25);

      // Add stats summary with filtered counts
      doc.setFont("MontserratBold");
      doc.text("Summary", 14, 35);
      doc.setFont("MontserratRegular");
      doc.text(`Total Filtered Alerts: ${filteredData.length}`, 14, 45);
      doc.text(`High Severity: ${filteredData.filter((alert: SecurityAlert) => alert.severity === "High").length}`, 14, 50);
      doc.text(`Medium Severity: ${filteredData.filter((alert: SecurityAlert) => alert.severity === "Medium").length}`, 14, 55);
      doc.text(`Low Severity: ${filteredData.filter((alert: SecurityAlert) => alert.severity === "Low").length}`, 14, 60);

      // Prepare table data
      const tableData = filteredData.map((alert: SecurityAlert) => [
        alert.id,
        alert.type,
        alert.user,
        alert.details,
        formatDateForCsv(alert.time),
        alert.severity,
        alert.resolved ? "Resolved" : "Unresolved"
      ]);

      // Add table
      autoTable(doc, {
        head: [["ID", "Type", "User", "Details", "Time", "Severity", "Status"]],
        body: tableData,
        startY: 70, // Increased spacing from the top content
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
          1: { cellWidth: 25 }, // Type
          2: { cellWidth: 25 }, // User
          3: { cellWidth: 45 }, // Details
          4: { cellWidth: 25 }, // Time
          5: { cellWidth: 18 }, // Severity
          6: { cellWidth: 25 }, // Status
        },
        didParseCell: (data) => {
          // Color the severity cell based on the value
          if (data.column.dataKey === 5) {
            if (data.cell.raw === "High") {
              data.cell.styles.textColor = [255, 0, 0]; // Red
            } else if (data.cell.raw === "Medium") {
              data.cell.styles.textColor = [255, 165, 0]; // Orange
            } else if (data.cell.raw === "Low") {
              data.cell.styles.textColor = [0, 128, 0]; // Green
            }
          }
        }
      });

      // Save the PDF
      doc.save(`Argus-AI-Security-Alerts-${new Date().toISOString().slice(0, 10)}.pdf`);

    } catch (error) {
      console.error('Error exporting PDF:', error);
    }
  };

  // Function to export alerts as CSV
  const exportAlerts = async () => {
    try {
      if (!table || !alerts.length) return;

      // Get filtered data
      const filteredData = table.getFilteredRowModel().rows.map((row) => row.original);
      
      if (filteredData.length === 0) return;

      const headers = ["ID", "Type", "User", "Details", "Time", "Severity", "Status"];
      const csvData = filteredData.map((alert: SecurityAlert) => [
        alert.id,
        alert.type,
        alert.user,
        alert.details,
        formatDateForCsv(alert.time),
        alert.severity,
        alert.resolved ? "Resolved" : "Unresolved"
      ]);

      const csvContent = [
        headers.join(","),
        ...csvData.map(row => row.map(escapeCsvValue).join(","))
      ].join("\n");

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", `Argus-AI-Security-Alerts-${new Date().toISOString().slice(0, 10)}.csv`);
      link.style.visibility = "hidden";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url); // Clean up the URL object
    } catch (error) {
      console.error('Error exporting alerts:', error);
    }
  };

  // Calculate total pages safely

  return (
      <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
        <div className="flex items-center justify-between">
          <h2 className="text-3xl font-bold tracking-tight">Security Overview</h2>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                disabled={alerts.length === 0 || loading}
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
                  await exportAlerts();
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

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle className="text-sm font-medium">All Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {stats?.alertStats?.total || alerts.length || 0}
              </div>
              <div className="mt-2 flex gap-2">
                <Badge variant="outline" className="text-xs text-red-700 dark:text-red-400 border-red-300 dark:border-red-700">
                  {stats?.alertStats?.bySeverity?.High || alerts.filter(a => a.severity === "High").length || 0} High
                </Badge>
                <Badge variant="outline" className="text-xs text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700">
                  {stats?.alertStats?.bySeverity?.Medium || alerts.filter(a => a.severity === "Medium").length || 0} Medium
                </Badge>
                <Badge variant="outline" className="text-xs text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
                  {stats?.alertStats?.bySeverity?.Low || alerts.filter(a => a.severity === "Low").length || 0} Low
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Security Score</CardTitle>
              <Shield className="h-4 w-4 text-teal-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {stats?.securityScore?.current?.toFixed(1) || '0.0'}%
              </div>
              <div className="mt-2">
                <Progress value={stats?.securityScore?.current || 0} className="h-2" />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Based on security key adoption
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.activeSessions?.total || 0}</div>
              <div className="mt-2 space-y-1 max-h-20 overflow-auto">
                {stats?.activeSessions?.byDevice && Object.entries(stats.activeSessions.byDevice).map(([device, count]) => (
                    <div key={device} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">{device}</span>
                      <span className="font-medium">{count}</span>
                    </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Across {stats?.activeSessions?.uniqueDevices || 0} unique devices
              </p>
            </CardContent>
          </Card>
        </div>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Security Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
                <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
                  <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
                  <span>Loading security alerts...</span>
                </div>
            ) : error ? (
                <div className="text-center py-8 text-red-500">{error}</div>
            ) : (
                <div className="space-y-4">
                  <DataTable
                      columns={columns}
                      data={alerts}
                      pageCount={pageCount}
                      onTableInit={handleTableInit}
                      state={{
                        sorting,
                        columnFilters,
                        columnVisibility,
                        rowSelection,
                        pagination
                      }}
                      onSortingChange={setSorting}
                      onColumnFiltersChange={setColumnFilters}
                      onColumnVisibilityChange={setColumnVisibility}
                      onRowSelectionChange={setRowSelection}
                      onPaginationChange={setPagination}
                      enableRowSelection={true}
                      toolbar={(table) => (
                        <div className="flex items-center space-x-4 w-full font-montserrat">
                          <Select
                            value={severityFilterValue}
                            onValueChange={(value) => {
                              setSeverityFilterValue(value);
                            }}
                          >
                            <SelectTrigger className="w-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                              <SelectValue placeholder="Filter by severity" />
                            </SelectTrigger>
                            <SelectContent>
                              {severityOptions.map((option) => (
                                <SelectItem key={option.value} value={option.value}>
                                  {option.label}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>

                          <Select
                            value={typeFilterValue}
                            onValueChange={(value) => {
                              setTypeFilterValue(value);
                            }}
                          >
                            <SelectTrigger className="w-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                              <SelectValue placeholder="Filter by type" />
                            </SelectTrigger>
                            <SelectContent>
                              {alertTypeOptions.map(option => (
                                <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="outline" className="ml-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
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

                  {alerts.length === 0 && !loading && (
                      <div className="text-center py-8 text-muted-foreground">
                        No security alerts found
                      </div>
                  )}
                </div>
            )}
          </CardContent>
        </Card>
      </div>
  )
}

