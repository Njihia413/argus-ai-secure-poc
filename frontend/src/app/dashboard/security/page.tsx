"use client"

import { useEffect, useState } from "react"
import {
  AlertTriangle,
  Shield,
  Clock,
  MapPin,
  Laptop,
  UserX,
  User,
  Lock,
  Globe,
  AlertCircle,
  ArrowDownUp
} from "lucide-react"
import { API_URL } from "@/app/utils/constants"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { DataTable } from "@/components/data-table/data-table"
import { ColumnDef, Table } from "@tanstack/react-table"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Progress } from "@/components/ui/progress"

// Types for our API responses
type SecurityAlert = {
  id: number
  type: string
  user: string
  details: string
  time: string
  severity: "High" | "Medium" | "Low"
  resolved: boolean
}

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

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [stats, setStats] = useState<SecurityStats>(emptyStats)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(10)
  const [table, setTable] = useState<Table<SecurityAlert> | null>(null)
  const [severityFilterValue, setSeverityFilterValue] = useState<string>("all");
  const [typeFilterValue, setTypeFilterValue] = useState<string>("all");

  // Column definitions with appropriate icons for each alert type
  const columns: ColumnDef<SecurityAlert>[] = [
    {
      accessorKey: "type",
      header: "Type",
      filterFn: (row, id, filterValue) => {
        if (typeof filterValue !== 'string') return true;
        // Adjust filter logic for "all" value
        return filterValue === "all" || row.getValue(id) === filterValue
      },
      cell: ({ row }) => {
        const alert = row.original

        // Select the appropriate icon based on the alert type
        const getAlertIcon = (type: string) => {
          switch(type) {
            case "Failed Login":
              return <UserX className="h-4 w-4 mr-2 text-red-500" />
            case "New IP Address":
              return <Globe className="h-4 w-4 mr-2 text-blue-500" />
            case "Suspicious IP":
              return <AlertTriangle className="h-4 w-4 mr-2 text-red-500" />
            case "Account Lockout":
              return <Lock className="h-4 w-4 mr-2 text-red-500" />
            case "New Device":
              return <Laptop className="h-4 w-4 mr-2 text-blue-500" />
            case "Unusual Time":
              return <Clock className="h-4 w-4 mr-2 text-amber-500" />
            case "Location Change":
              return <MapPin className="h-4 w-4 mr-2 text-amber-500" />
            case "Rapid Travel":
              return <ArrowDownUp className="h-4 w-4 mr-2 text-red-500" />
            case "High Risk Login":
              return <AlertCircle className="h-4 w-4 mr-2 text-red-500" />
            case "Moderate Risk Login":
              return <AlertCircle className="h-4 w-4 mr-2 text-amber-500" />
            case "Admin Account Login":
              return <User className="h-4 w-4 mr-2 text-blue-500" />
            default:
              return <Shield className="h-4 w-4 mr-2 text-gray-500" />
          }
        }

        return (
            <div className="flex items-center">
              {getAlertIcon(alert.type)}
              {alert.type}
            </div>
        )
      }
    },
    {
      accessorKey: "user",
      header: "User"
    },
    {
      accessorKey: "details",
      header: "Details",
    },
    {
      accessorKey: "time",
      header: "Time",
      cell: ({ row }) => {
        // Format the timestamp for better readability
        const isoTime = row.getValue<string>("time");
        try {
          const date = new Date(isoTime);
          return date.toLocaleString();
        } catch (e) {
          return isoTime;
        }
      }
    },
    {
      accessorKey: "severity",
      header: "Severity",
      filterFn: (row, id, filterValue) => {
        if (typeof filterValue !== 'string') return true;
        // Adjust filter logic for "all" value
        return filterValue === "all" || row.getValue(id) === filterValue
      },
      cell: ({ row }) => {
        const alert = row.original
        return (
            <Badge
                variant="outline"
                className={
                  alert.severity === "High"
                      ? "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700"
                      : alert.severity === "Medium"
                          ? "text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-700"
                          : "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700"
                }
            >
              {alert.severity}
            </Badge>
        )
      }
    },
    // {
    //   accessorKey: "resolved",
    //   header: "Status",
    //   cell: ({ row }: { row: { original: SecurityAlert } }) => {
    //     const alert = row.original
    //     return (
    //         <Badge
    //             variant="outline"
    //             className={alert.resolved ? "bg-green-50 text-green-700 border-green-200" : "bg-red-50 text-red-700 border-red-200"}
    //         >
    //           {alert.resolved ? "Resolved" : "Unresolved"}
    //         </Badge>
    //     )
    //   }
    // }
  ]

  // Handle table reference
  const handleTableInit = (tableInstance: Table<SecurityAlert>) => {
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
        const alertsRes = await fetch(`${API_URL}/security/alerts`, {
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
  }, [pageIndex, pageSize])

  // Function to export alerts as CSV
  const exportAlerts = () => {
    if (!alerts.length) return;

    const headers = ["Type", "User", "Details", "Time", "Severity", "Status"];
    const csvData = alerts.map(alert => [
      alert.type,
      alert.user,
      alert.details,
      alert.time,
      alert.severity,
      alert.resolved ? "Resolved" : "Unresolved"
    ]);

    const csvContent = [
      headers.join(","),
      ...csvData.map(row => row.map(cell => `"${cell}"`).join(","))
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `security-alerts-${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Calculate total pages safely
  const getTotalPages = () => {
    // Use alerts length as fallback if stats is not available
    const totalItems = stats?.alertStats?.total || alerts.length || 0;
    return Math.max(1, Math.ceil(totalItems / pageSize));
  };

  return (
      <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
        <div className="flex items-center justify-between">
          <h2 className="text-3xl font-bold tracking-tight">Security Overview</h2>
          <Button
              onClick={exportAlerts}
              disabled={alerts.length === 0 || loading}
          >
            Export Report
          </Button>
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
                <div className="text-center py-8">Loading security alerts...</div>
            ) : error ? (
                <div className="text-center py-8 text-red-500">{error}</div>
            ) : (
                <div className="space-y-4">
                  {/* Filters for the DataTable */}
                  <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                    <div className="flex flex-wrap space-x-2 gap-y-2">
                      <Select
                          value={severityFilterValue}
                          onValueChange={(value) => {
                            setSeverityFilterValue(value);
                            const column = table?.getColumn("severity");
                            if (column) {
                              column.setFilterValue(value === "all" ? undefined : value);
                            }
                          }}
                      >
                        <SelectTrigger className="w-[180px] border border-input">
                          <SelectValue placeholder="Filter by severity" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Severities</SelectItem>
                          <SelectItem value="High">High</SelectItem>
                          <SelectItem value="Medium">Medium</SelectItem>
                          <SelectItem value="Low">Low</SelectItem>
                        </SelectContent>
                      </Select>

                      <Select
                          value={typeFilterValue}
                          onValueChange={(value) => {
                            setTypeFilterValue(value);
                            const column = table?.getColumn("type");
                            if (column) {
                              column.setFilterValue(value === "all" ? undefined : value);
                            }
                          }}
                      >
                        <SelectTrigger className="w-[180px] border border-input">
                          <SelectValue placeholder="Filter by type" />
                        </SelectTrigger>
                        <SelectContent>
                          {alertTypeOptions.map(option => (
                              <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {table && alerts.length > 0 && (
                        <div className="text-sm text-muted-foreground">
                          Showing {table.getFilteredRowModel().rows.length} of {alerts.length} alerts
                        </div>
                    )}
                  </div>

                  {/* DataTable */}
                  <DataTable<SecurityAlert, unknown>
                      columns={columns}
                      data={alerts}
                      onTableInit={handleTableInit}
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