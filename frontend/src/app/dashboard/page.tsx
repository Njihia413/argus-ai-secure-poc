"use client"

import { useState, useEffect, useCallback } from "react"
import React from "react"
import { API_URL } from "@/app/utils/constants"
import {
  BarChart3,
  Shield,
  Bell,
  ArrowUpRight,
  ArrowDownRight,
  Laptop,
  Smartphone,
  Tablet,
} from "lucide-react"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Area,
  AreaChart,
  Line,
  LineChart,
  Pie,
  PieChart,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Legend,
  Tooltip,
  Cell
} from "recharts"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  ChartConfig,
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart"

interface ChartErrorState {
  hasError: boolean;
}

interface ChartErrorProps {
  children: React.ReactNode;
}

class ChartErrorBoundary extends React.Component<ChartErrorProps, ChartErrorState> {
  constructor(props: ChartErrorProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ChartErrorState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error('Chart Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="h-full flex items-center justify-center text-muted-foreground">
          Error loading chart. Please try again.
        </div>
      );
    }

    return this.props.children;
  }
}

interface Stats {
  totalLogins: number;
  loginChange?: number;
  securityScore?: number;
  successRate?: number;
  failedAttempts: number;
  failedChange?: number;
}

interface LoginAttempt {
  name: string;
  successful: number;
  failed: number;
}

interface SecurityMetric {
  name: string;
  value: number;
  color?: string;
}

interface LocationStat {
  name: string;
  value: number;
  severity: 'high' | 'medium' | 'low';
}

interface DeviceStat {
  name: string;
  value: number;
}

interface RiskTrendItem {
  name: string;
  riskScore: number;
  attemptCount?: number;
}

interface StoredUser {
  authToken: string;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loginAttempts, setLoginAttempts] = useState<LoginAttempt[]>([]);
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetric[]>([]);
  const [locationStats, setLocationStats] = useState<LocationStat[]>([]);
  const [deviceStats, setDeviceStats] = useState<DeviceStat[]>([]);
  const [riskTrend, setRiskTrend] = useState<RiskTrendItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  // Add refresh trigger state for dashboard updates
  const [refreshTrigger, setRefreshTrigger] = useState(0)

  // Function to trigger a refresh of dashboard data
  const triggerRefresh = useCallback(() => {
    console.log("Triggering dashboard refresh")
    setRefreshTrigger(prev => prev + 1)
  }, [])

  // Function to toggle security key status
  const toggleKeyStatus = async (keyId: string) => {
    try {
      setIsLoading(true)
      const userStr = sessionStorage.getItem('user')
      if (!userStr) {
        throw new Error('User not authenticated')
      }
      const user = JSON.parse(userStr) as StoredUser;
      const authToken = user.authToken;

      const response = await fetch(`${API_URL}/security-keys/${keyId}/toggle-status`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        }
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to toggle key status')
      }

      const result = await response.json()
      console.log('Key status updated:', result)

      // Trigger dashboard refresh
      triggerRefresh()

      return result
    } catch (error: any) {
      console.error('Error toggling key status:', error);
      setError(error.message);
      throw error;
    } finally {
      setIsLoading(false)
    }
  }

  // Function to delete a security key
  const deleteSecurityKey = async (keyId: string) => {
    try {
      setIsLoading(true)
      const userStr = sessionStorage.getItem('user')
      if (!userStr) {
        throw new Error('User not authenticated')
      }
      const user = JSON.parse(userStr) as StoredUser;
      const authToken = user.authToken;

      const response = await fetch(`${API_URL}/security-keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${authToken}`
        }
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Failed to delete security key')
      }

      const result = await response.json()
      console.log('Security key deleted:', result)

      // Trigger refresh of dashboard data
      triggerRefresh()

      return result
    } catch (error: any) {
      console.error('Error deleting security key:', error);
      setError(error.message);
      throw error;
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    console.log("Starting data fetch...")
    setIsLoading(true)
    async function fetchDashboardData() {
      try {
        // Get auth token from sessionStorage
        const userStr = sessionStorage.getItem('user')
        if (!userStr) {
          throw new Error('User not authenticated')
        }
        const user = JSON.parse(userStr) as StoredUser;
        const authToken = user.authToken;
        const headers = {
          'Authorization': `Bearer ${authToken}`
        }

        // Fetch overview stats
        const statsResponse = await fetch(`${API_URL}/dashboard-stats`, { headers })
        if (!statsResponse.ok) {
          throw new Error('Failed to fetch dashboard stats')
        }
        const statsData = await statsResponse.json()
        setStats(statsData)

        // Fetch login attempts data
        const loginResponse = await fetch(`${API_URL}/login-attempts`, { headers })
        if (!loginResponse.ok) {
          throw new Error(`Failed to fetch login attempts for range ${timeRange}`)
        }
        const loginData = await loginResponse.json()
        if (!loginData || !loginData.attempts) {
          throw new Error('Invalid login attempts data')
        }
        console.log('Login attempts data received:', loginData.attempts)
        if (!Array.isArray(loginData.attempts)) {
          throw new Error('Login attempts data is not an array')
        }
        if (loginData.attempts.length === 0) {
          console.log('No login attempts data available')
        } else {
          console.log('First login attempt:', loginData.attempts[0])
          console.log('Total login attempts:', loginData.attempts.length)
        }
        setLoginAttempts(loginData.attempts)

        // Fetch security metrics with enhanced data
        const metricsResponse = await fetch(`${API_URL}/security-metrics`, { headers })
        if (!metricsResponse.ok) {
          throw new Error('Failed to fetch security metrics')
        }
        const metricsData = await metricsResponse.json()
        console.log("Security metrics data:", metricsData)

        // Use metrics data directly from the API
        setSecurityMetrics(metricsData.metrics || [])

        // Fetch device distribution stats
        const deviceResponse = await fetch(`${API_URL}/device-stats`, { headers })
        if (!deviceResponse.ok) {
          throw new Error('Failed to fetch device stats')
        }
        const deviceData = await deviceResponse.json()
        setDeviceStats(deviceData.deviceStats)

        // Fetch location statistics
        const locationResponse = await fetch(`${API_URL}/location-stats`, { headers })
        if (!locationResponse.ok) {
          throw new Error('Failed to fetch location stats')
        }
        const locationData = await locationResponse.json()
        setLocationStats(locationData.locationStats)

        const riskTrendResponse = await fetch(`${API_URL}/risk-score-trend`, { headers })
        if (!riskTrendResponse.ok) {
          throw new Error('Failed to fetch risk score trend')
        }
        const riskTrendData = await riskTrendResponse.json()
        setRiskTrend(riskTrendData.riskTrend)

      } catch (error: any) {
        console.error('Error fetching dashboard data:', error);
        setError(error?.message || 'An error occurred');
      } finally {
        setIsLoading(false)
      }
    }

    fetchDashboardData()
  }, [refreshTrigger, timeRange]) // Add refreshTrigger and timeRange to dependency array

  const DEVICE_COLOR_MAP: { [key: string]: string } = {
    'windows pc': '#2563eb',
    'desktop': '#2563eb', // Assuming general 'Desktop' might also map to Windows or be a fallback
    'mobile': '#a6c4fc',
    'tablet': '#60A5FA',
    'mac': '#8B5CF6',
    'linux': '#C4B5FD',
    'others': '#9CA3AF', // Default for 'Others'
    'unknown': '#9CA3AF' // Fallback for unknown or null device types
  };

  // Helper function for bar color based on risk score
  const getRiskColor = (score: number) => {
    if (score > 75) return "#8B5CF6" // Purple for High Risk
    if (score > 40) return "#2563eb" // Primary Blue for Medium Risk
    return "#a6c4fc" // Light Blue for Low Risk
  }

  const formatRiskScore = (score: number | string | (string | number)[] | null | undefined) => {
    if (Array.isArray(score)) {
      score = score[0]; // Take first value if array
    }
    if (typeof score === 'number') {
      return score.toFixed(1)
    } else if (score !== undefined && score !== null && typeof score === 'string' && !isNaN(parseFloat(score))) {
      return parseFloat(score.toString()).toFixed(1)
    } else {
      return "N/A"
    }
  }
 
  const loginAttemptsChartConfig = {
    // Ensure 'name' is present if used as dataKey for XAxis in some contexts,
    // or rely on direct dataKey in XAxis component.
    // For series colors, ChartContainer will create CSS vars like --color-successful
    successful: {
      label: "Successful",
      color: "#8B5CF6", // As per your feedback
    },
    failed: {
      label: "Failed",
      color: "var(--chart-4)", // Your existing theme variable for the second color
    },
  } satisfies ChartConfig;
 
  return (
    <div className="flex flex-col gap-6">
        <h2 className="text-2xl font-bold tracking-tight">Dashboard Overview</h2>
 
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {/* Overview Stats */}
          <Card className="shadow-sm hover:shadow-md transition-shadow bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)]">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Logins</CardTitle>
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{stats?.totalLogins || 0}</div>
              <p className="text-xs text-muted-foreground">
                {stats?.loginChange !== undefined
                    ? `${stats.loginChange > 0 ? '+' : ''}${stats.loginChange}`
                    : '0'}% from last month
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)]">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Security Score</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{stats?.securityScore || 0}%</div>
              <div className="mt-2">
                <Progress value={stats?.securityScore || 0} className="h-2 bg-foreground/20 [&>div]:bg-foreground" />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Based on security key adoption
              </p>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)]">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Successful Logins</CardTitle>
              <Bell className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{stats?.successRate || 0}%</div>
              <div className="mt-2 flex gap-2">
                <Badge
                    variant="outline"
                    className={`text-xs ${
                        stats?.successRate !== undefined ? (
                            stats.successRate >= 90
                                ? 'text-green-500 border-green-500 dark:text-green-400 dark:border-green-400'
                                : stats.successRate >= 70
                                    ? 'text-amber-500 border-amber-500 dark:text-amber-400 dark:border-amber-400'
                                    : 'text-red-500 border-red-500 dark:text-red-400 dark:border-red-400'
                        ) : 'text-muted-foreground border-muted-foreground'
                    } bg-transparent`}
                >
                  {stats?.successRate !== undefined ? (
                      stats.successRate >= 90 ? 'High' : stats.successRate >= 70 ? 'Medium' : 'Low'
                  ) : 'N/A'}
                </Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)]">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Failed Attempts</CardTitle>
              <ArrowDownRight className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{stats?.failedAttempts || 0}</div>
              <p className="text-xs text-muted-foreground">
                {stats?.failedChange !== undefined
                    ? `${stats.failedChange > 0 ? '+' : ''}${stats.failedChange}`
                    : '0'}% from last month
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {/* Login Attempts Chart */}
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            {/* Using exact CardHeader structure from example */}
            <CardHeader className="flex items-center gap-2 space-y-0 border-b py-5 sm:flex-row">
              <div className="grid flex-1 gap-1 text-center sm:text-left">
                <CardTitle>Login Attempts</CardTitle>
                <CardDescription>
                  {timeRange === '7d' && 'Showing login attempts for the last 7 days'}
                  {timeRange === '30d' && 'Showing login attempts for the last 30 days'}
                  {timeRange === '90d' && 'Showing login attempts for the last 3 months'}
                </CardDescription>
              </div>
              <Select value={timeRange} onValueChange={(value) => setTimeRange(value as '7d' | '30d' | '90d')}>
                <SelectTrigger
                  className="w-[160px] rounded-lg sm:ml-auto"
                  aria-label="Select a time range"
                >
                  <SelectValue placeholder="Select time range" />
                </SelectTrigger>
                <SelectContent className="rounded-xl">
                  <SelectItem value="90d" className="rounded-lg">
                    Last 3 months
                  </SelectItem>
                  <SelectItem value="30d" className="rounded-lg">
                    Last 30 days
                  </SelectItem>
                  <SelectItem value="7d" className="rounded-lg">
                    Last 7 days
                  </SelectItem>
                </SelectContent>
              </Select>
            </CardHeader>
            {/* Using exact CardContent structure and padding from example */}
            <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
              <ChartErrorBoundary>
                {isLoading ? (
                  <div className="aspect-auto h-[250px] w-full flex items-center justify-center text-muted-foreground">
                    Loading login attempts data...
                  </div>
                ) : error ? (
                  <div className="aspect-auto h-[250px] w-full flex items-center justify-center text-red-500">
                    {error}
                  </div>
                ) : loginAttempts.length === 0 ? (
                  <div className="aspect-auto h-[250px] w-full flex items-center justify-center text-muted-foreground">
                    No login attempts data available for the selected period.
                  </div>
                ) : (
                  <ChartContainer
                    config={loginAttemptsChartConfig}
                    className="aspect-auto h-[250px] w-full"
                  >
                    <AreaChart
                      accessibilityLayer
                      data={loginAttempts} // Corrected to use loginAttempts
                      margin={{ // Matching example margins
                        left: 12,
                        right: 12,
                        top: 5,
                        bottom: 5,
                      }}
                    >
                      <defs>
                        <linearGradient id="fillSuccessful" x1="0" y1="0" x2="0" y2="1">
                          <stop
                            offset="5%"
                            stopColor="var(--color-successful)" // Uses color from chartConfig
                            stopOpacity={0.8}
                          />
                          <stop
                            offset="95%"
                            stopColor="var(--color-successful)"
                            stopOpacity={0.1}
                          />
                        </linearGradient>
                        <linearGradient id="fillFailed" x1="0" y1="0" x2="0" y2="1">
                          <stop
                            offset="5%"
                            stopColor="var(--color-failed)" // Uses color from chartConfig
                            stopOpacity={0.8}
                          />
                          <stop
                            offset="95%"
                            stopColor="var(--color-failed)"
                            stopOpacity={0.1}
                          />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} /> {/* Matching example */}
                      <XAxis
                        dataKey="name" // Your data key for date/label
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        minTickGap={32} // Matching example
                        tickFormatter={(value) => {
                          try {
                            const date = new Date(value);
                            // Fallback for non-standard date strings if 'name' isn't directly parsable
                            if (isNaN(date.getTime())) {
                              // Attempt to parse if it's like "Mon DD"
                              const parts = value.split(" ");
                              if (parts.length === 2) {
                                const monthDate = new Date(`${parts[0]} ${parts[1]}, ${new Date().getFullYear()}`);
                                if (!isNaN(monthDate.getTime())) {
                                   return monthDate.toLocaleDateString("en-US", {month: "short", day: "numeric"});
                                }
                              }
                              return value; // Return original value if parsing fails
                            }
                            return date.toLocaleDateString("en-US", {
                              month: "short",
                              day: "numeric",
                            });
                          } catch (e) {
                            return value;
                          }
                        }}
                      />
                      {/* YAxis is omitted to let Recharts auto-configure, as in the example */}
                      <ChartTooltip
                        cursor={false} // Matching example
                        content={
                          <ChartTooltipContent
                            labelFormatter={(value) => { // Value here is the XAxis dataKey ('name')
                              try {
                                const date = new Date(value);
                                if (isNaN(date.getTime())) {
                                   const parts = value.split(" ");
                                   if (parts.length === 2) {
                                     const monthDate = new Date(`${parts[0]} ${parts[1]}, ${new Date().getFullYear()}`);
                                     if (!isNaN(monthDate.getTime())) {
                                       return monthDate.toLocaleDateString("en-US", {month: "short", day: "numeric"});
                                     }
                                   }
                                  return value;
                                }
                                return date.toLocaleDateString("en-US", {
                                  month: "short",
                                  day: "numeric",
                                });
                              } catch (e) {
                                return value;
                              }
                            }}
                            indicator="dot" // Matching example
                          />
                        }
                      />
                      <Area
                        dataKey="successful" // Your data key
                        type="natural"
                        fill="url(#fillSuccessful)"
                        stroke="var(--color-successful)"
                        stackId="a" // For stacked areas, as in the example image
                      />
                      <Area
                        dataKey="failed" // Your data key
                        type="natural"
                        fill="url(#fillFailed)"
                        stroke="var(--color-failed)"
                        stackId="a" // For stacked areas, as in the example image
                      />
                      <ChartLegend content={<ChartLegendContent />} />
                    </AreaChart>
                  </ChartContainer>
                )}
              </ChartErrorBoundary>
            </CardContent>
          </Card>

          {/* Risk Score Chart */}
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Risk Score Trend</CardTitle>
              <CardDescription>Average risk assessment score trend</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ChartErrorBoundary>
                  {isLoading ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        Loading risk score trend...
                      </div>
                  ) : error ? (
                      <div className="h-full flex items-center justify-center text-red-500">
                        {error}
                      </div>
                  ) : riskTrend?.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        No risk score data available
                      </div>
                  ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                            data={riskTrend?.length > 0 ? riskTrend.map(item => ({
                              ...item,
                              riskScore: item.riskScore || 0 // Ensure riskScore is a number
                            })) : [{ name: 'No Data', riskScore: 0 }]}
                            margin={{ top: 10, right: 10, left: 10, bottom: 0 }}
                        >
                          <XAxis
                              dataKey="name"
                              stroke="#888888"
                              fontSize={12}
                              tickLine={false}
                              axisLine={false}
                          />
                          <YAxis
                              stroke="#888888"
                              fontSize={12}
                              tickLine={false}
                              axisLine={false}
                              tickFormatter={(value) => Math.round(value).toString()}
                              allowDecimals={false}
                              domain={[0, 100]} // Risk score is 0-100
                          />
                          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                          <Bar dataKey="riskScore" name="Avg Risk Score">
                            {(riskTrend || []).map((entry, index) => (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={getRiskColor(entry.riskScore || 0)}
                                />
                            ))}
                          </Bar>
                          <Tooltip
                            formatter={(value: number | string | Array<number | string>) => [
                              formatRiskScore(value),
                              "Avg Risk Score"
                            ]}
                            labelFormatter={(label) => `${label}`}
                            content={({ active, payload, label }) => {
                              if (active && payload && payload.length) {
                                const data = payload[0].payload as RiskTrendItem;
                                return (
                                  <div className="rounded-lg border bg-background p-2 shadow-sm text-sm text-foreground">
                                    <div className="font-bold">{label}</div>
                                    <div>
                                      Avg Risk: <span style={{ color: getRiskColor(data.riskScore) }}>{formatRiskScore(data.riskScore)}</span>
                                    </div>
                                    {data.attemptCount !== undefined && (
                                      <div className="text-xs text-muted-foreground">
                                        Attempts: {data.attemptCount}
                                      </div>
                                    )}
                                  </div>
                                );
                              }
                              return null;
                            }}
                          />
                        </BarChart>
                      </ResponsiveContainer>
                  )}
                </ChartErrorBoundary>
              </div>
              {/* Custom Legend for Risk Score Colors */}
              <div className="mt-4 flex justify-center space-x-4 text-xs text-foreground">
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#a6c4fc' }}></span>
                  Low Risk
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#2563eb' }}></span>
                  Medium Risk
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#8B5CF6' }}></span>
                  High Risk
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          {/* Security Metrics Pie Chart */}
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Security Metrics</CardTitle>
              <CardDescription>Distribution of security keys across users</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ChartErrorBoundary>
                  {isLoading ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        Loading security metrics...
                      </div>
                  ) : error ? (
                      <div className="h-full flex items-center justify-center text-red-500">
                        {error}
                      </div>
                  ) : securityMetrics.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        No security metrics data available
                      </div>
                  ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                          <Pie
                              data={securityMetrics}
                              dataKey="value"
                              nameKey="name"
                              cx="50%"
                              cy="50%"
                              outerRadius={80}
                              stroke="none" // Remove border from pie segments
                          >
                            {securityMetrics.map((entry, index) => (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={entry.color || "#6B7280"} // Use the color from our data
                                />
                            ))}
                          </Pie>
                          <Tooltip
                              content={({ active, payload, label }) => {
                                if (active && payload && payload.length) {
                                  const data = payload[0].payload as SecurityMetric; // Added type assertion
                                  return (
                                      <div className="rounded-lg bg-background p-2 shadow-sm text-sm text-foreground">
                                        <p className="font-bold">{data.name}</p>
                                        <p>{data.value} users</p>
                                      </div>
                                  );
                                }
                                return null;
                              }}
                            />
                        </PieChart>
                      </ResponsiveContainer>
                  )}
                </ChartErrorBoundary>
              </div>
              {/* Custom Legend with colored boxes */}
              <div className="mt-4 flex justify-center space-x-4 text-xs text-foreground">
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#2563eb' }}></span>
                  Active Keys
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#a6c4fc' }}></span>
                  Inactive Keys
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#8B5CF6' }}></span>
                  No Keys
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Device Breakdown */}
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Device Distribution</CardTitle>
              <CardDescription>Login attempts by device type</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ChartErrorBoundary>
                  {isLoading ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        Loading device stats...
                      </div>
                  ) : error ? (
                      <div className="h-full flex items-center justify-center text-red-500">
                        {error}
                      </div>
                  ) : deviceStats.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        No device data available
                      </div>
                  ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                          <Pie
                              data={deviceStats}
                              dataKey="value"
                              nameKey="name"
                              cx="50%"
                              cy="50%"
                              outerRadius={80}
                              stroke="none" // Remove border from pie segments
                          >
                            {deviceStats.map((entry, index) => {
                              const deviceName = entry.name ? entry.name.toLowerCase() : 'unknown';
                              const color = DEVICE_COLOR_MAP[deviceName] || DEVICE_COLOR_MAP['others'];
                              return (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={color}
                                />
                              );
                            })}
                          </Pie>
                          <Tooltip
                              formatter={(value) => [`${value} attempts`, "Logins"]}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                  )}
                </ChartErrorBoundary>
              </div>
              {/* Custom Legend for Device Distribution */}
              {!isLoading && !error && deviceStats.length > 0 && (
                <div className="mt-4 flex flex-wrap justify-center space-x-4 text-xs text-foreground">
                  {Object.entries(
                    // Create a unique set of device names and their colors for the legend
                    deviceStats.reduce((acc, entry) => {
                      const deviceName = entry.name ? entry.name : 'Unknown';
                      const color = DEVICE_COLOR_MAP[deviceName.toLowerCase()] || DEVICE_COLOR_MAP['others'];
                      if (!acc[deviceName]) {
                        acc[deviceName] = color;
                      }
                      return acc;
                    }, {} as Record<string, string>)
                  ).map(([name, color]) => (
                    <div key={name} className="flex items-center mb-2">
                      <span
                        className="w-3 h-3 rounded-sm mr-1.5"
                        style={{ backgroundColor: color }}
                      ></span>
                      {name}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Location Statistics */}
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Top Locations</CardTitle>
              <CardDescription>Login attempts by location</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ChartErrorBoundary>
                  {isLoading ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        Loading location data...
                      </div>
                  ) : error ? (
                      <div className="h-full flex items-center justify-center text-red-500">
                        {error}
                      </div>
                  ) : locationStats.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-muted-foreground">
                        No location data available
                      </div>
                  ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                            data={locationStats}
                            margin={{ top: 5, right: 30, left: 30, bottom: 20 }}
                        >
                          <XAxis
                              dataKey="name"
                              tick={{ fontSize: 12 }}
                              interval={0}
                              angle={-45}
                              textAnchor="end"
                          />
                          <YAxis
                              type="number"
                              allowDecimals={false}
                              domain={[0, 'auto']}
                              tickFormatter={(value) => Math.round(value).toString()}
                          />
                          <CartesianGrid strokeDasharray="3 3" />
                          <Bar dataKey="value" name="Attempts">
                            {locationStats.map((entry, index) => (
                                <Cell
                                    key={`cell-${index}`}
                                    fill={entry.severity === 'high'
                                        ? '#8B5CF6' // High severity - Purple
                                        : entry.severity === 'medium'
                                            ? '#2563eb' // Medium severity - Primary Blue
                                            : '#a6c4fc'   // Low severity - Light Blue
                                    }
                                />
                            ))}
                          </Bar>
                          <Tooltip
                              formatter={(value) => [`${value} attempts`, 'Count']}
                          />
                        </BarChart>
                      </ResponsiveContainer>
                  )}
                </ChartErrorBoundary>
              </div>
              {/* Custom Legend for Location Severity Colors */}
              <div className="mt-4 flex justify-center space-x-4 text-xs text-foreground">
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#a6c4fc' }}></span>
                  {'Low (<= 5 attempts)'}
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#2563eb' }}></span>
                  {'Medium (<= 15 attempts)'}
                </div>
                <div className="flex items-center">
                  <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#8B5CF6' }}></span>
                 {'High (> 15 attempts)'}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Optional: Security Keys Management Section
        Uncomment this section if you want to add direct key management to the dashboard
      
      <div className="mt-8">
        <h3 className="text-xl font-bold mb-4">Security Keys Management</h3>
        <div className="grid gap-4">
          {securityKeys.map(key => (
            <Card key={key.id} className="p-4 flex justify-between items-center">
              <div>
                <h4 className="font-medium">{key.name || `Key ${key.id}`}</h4>
                <p className="text-sm text-gray-500">
                  {key.isActive ? 'Active' : 'Inactive'} • Last used: {key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : 'Never'}
                </p>
              </div>
              <div className="flex space-x-2">
                <button
                  className={`px-3 py-1 text-sm rounded ${key.isActive ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-800'}`}
                  onClick={() => toggleKeyStatus(key.id)}
                >
                  {key.isActive ? 'Deactivate' : 'Activate'}
                </button>
                <button
                  className="px-3 py-1 text-sm rounded bg-red-500 text-white"
                  onClick={() => deleteSecurityKey(key.id)}
                >
                  Delete
                </button>
              </div>
            </Card>
          ))}
        </div>
      </div>
      */} {/* Closing the comment started on line 846 */}
      </div>
  )
}

