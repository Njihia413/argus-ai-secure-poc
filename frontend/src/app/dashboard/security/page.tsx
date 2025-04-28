"use client"

import { useEffect, useState } from "react"
import { AlertTriangle, Shield } from "lucide-react"
import { API_URL } from "@/app/utils/constants"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { SecurityDataTable } from "@/components/data-table/security-data-table"
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
const columns: ColumnDef<SecurityAlert, unknown>[] = [
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }: { row: { original: SecurityAlert } }) => {
      const alert = row.original
      return (
        <div className="flex items-center">
          <AlertTriangle
            className={`h-4 w-4 mr-2 ${
              alert.severity === "High"
                ? "text-red-500"
                : alert.severity === "Medium"
                  ? "text-amber-500"
                  : "text-green-500"
            }`}
          />
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
  },
  {
    accessorKey: "severity",
    header: "Severity",
    filterFn: (row, id, value) => {
      return value === "" || row.getValue(id) === value
    },
    cell: ({ row }: { row: { original: SecurityAlert } }) => {
      const alert = row.original
      return (
        <Badge
          variant={
            alert.severity === "High"
              ? "destructive"
              : alert.severity === "Medium"
                ? "outline"
                : "outline"
          }
          className={
            alert.severity === "High"
              ? "bg-red-50 text-red-700 border-red-200"
              : alert.severity === "Medium"
                ? "bg-amber-50 text-amber-700 border-amber-200"
                : "bg-green-50 text-green-700 border-green-200"
          }
        >
          {alert.severity}
        </Badge>
      )
    }
  }
]

export default function SecurityPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([])
  const [stats, setStats] = useState<SecurityStats>(emptyStats)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(10)
  const [table, setTable] = useState<Table<SecurityAlert> | null>(null)

  // Handle table reference
  const handleTableInit = (tableInstance: Table<SecurityAlert>) => {
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
        const user = JSON.parse(userStr)
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
        
        const alertsData = await alertsRes.json()

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

        const statsData = await statsRes.json()

        setAlerts(alertsData.alerts || [])
        setStats(statsData)
      } catch (error: any) {
        console.error('Error fetching security data:', error)
        setError(error.message || 'Failed to fetch security data')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [pageIndex, pageSize])

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Security Overview</h2>
        <Button onClick={() => {}} className="bg-black hover:bg-black/90 text-white">
          Export Report
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle className="text-sm font-medium">All Alerts</CardTitle>
          </CardHeader>
          <CardContent>
           <div className="text-2xl font-bold">{alerts.length}</div>
           <div className="mt-2 flex gap-2">
             <Badge variant="outline" className="text-xs bg-red-50 text-red-700 border-red-200">
               {alerts.filter(a => a.severity === "High").length} High
             </Badge>
             <Badge variant="outline" className="text-xs bg-amber-50 text-amber-700 border-amber-200">
               {alerts.filter(a => a.severity === "Medium").length} Medium
             </Badge>
             <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
               {alerts.filter(a => a.severity === "Low").length} Low
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
            <div className="text-2xl font-bold">{stats?.securityScore.current?.toFixed(1) || '0.0'}%</div>
            <div className="mt-2">
              <Progress value={stats?.securityScore.current || 0} className="h-2" />
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
           <div className="text-2xl font-bold">{stats?.activeSessions.total || 0}</div>
           <div className="mt-2 space-y-1">
             {stats?.activeSessions.byDevice && Object.entries(stats.activeSessions.byDevice).map(([device, count]) => (
               <div key={device} className="flex items-center justify-between text-xs">
                 <span className="text-muted-foreground">{device}</span>
                 <span className="font-medium">{count}</span>
               </div>
             ))}
           </div>
           <p className="text-xs text-muted-foreground mt-2">
             Across {stats?.activeSessions.uniqueDevices || 0} unique devices
           </p>
         </CardContent>
        </Card>
        </div>

        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Recent Security Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8">Loading security alerts...</div>
            ) : error ? (
              <div className="text-center py-8 text-red-500">{error}</div>
            ) : (
              <div className="space-y-4">
                {/* DataTable */}
                <SecurityDataTable
                  columns={columns}
                  data={alerts}
                  onTableInit={handleTableInit}
                />
              </div>
            )}
          </CardContent>
        </Card>
      </div>
  )
}