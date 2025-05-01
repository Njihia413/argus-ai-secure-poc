"use client"

import { useState, useEffect, useMemo } from "react"
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
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"

class ChartErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(_: Error) {
    return { hasError: true }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Chart Error:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="h-full flex items-center justify-center text-muted-foreground">
          Error loading chart. Please try again.
        </div>
      )
    }

    return this.props.children
  }
}

interface LoginAttempt {
  name: string
  successful: number
  failed: number
  riskScore: number
}

interface SecurityMetric {
  name: string
  value: number
}

interface DeviceStat {
  name: string
  value: number
}

interface LocationStat {
  name: string
  value: number
  severity: 'low' | 'medium' | 'high'
}

interface DashboardStats {
  totalLogins: number
  loginChange: number
  securityScore: number
  successRate: number
  failedAttempts: number
  failedChange: number
}

interface RiskTrend {
  name: string;
  riskScore: number;
  attemptCount: number;
}


export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loginAttempts, setLoginAttempts] = useState<LoginAttempt[]>([])
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetric[]>([])
  const [locationStats, setLocationStats] = useState<LocationStat[]>([])
  const [deviceStats, setDeviceStats] = useState<DeviceStat[]>([])
  const [riskTrend, setRiskTrend] = useState<RiskTrend[]>([]);
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // No need for processing since we're using backend data directly

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
        const user = JSON.parse(userStr)
        const authToken = user.authToken
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
          throw new Error('Failed to fetch login attempts')
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

        // Fetch security metrics
        const metricsResponse = await fetch(`${API_URL}/security-metrics`, { headers })
        if (!metricsResponse.ok) {
          throw new Error('Failed to fetch security metrics')
        }
        const metricsData = await metricsResponse.json()
        setSecurityMetrics(metricsData.metrics)

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

        const riskTrendResponse = await fetch(`${API_URL}/risk-score-trend`, { headers });
        if (!riskTrendResponse.ok) {
          throw new Error('Failed to fetch risk score trend');
        }
        const riskTrendData = await riskTrendResponse.json();
        setRiskTrend(riskTrendData.riskTrend);

      } catch (error) {
        console.error('Error fetching dashboard data:', error)
        // setError(error instanceof Error ? error.message : 'An error occurred') // Allow rendering other charts even if one fetch fails
      } finally {
        setIsLoading(false)
      }
    }

    fetchDashboardData()
  }, [])

  // Helper function for bar color based on risk score
  const getRiskColor = (score: number): string => {
    if (score > 75) return "#dc2626"; // Red for High Risk
    if (score > 40) return "#f59e0b"; // Amber for Medium Risk
    return "#16a34a"; // Green for Low Risk
  };

  const formatRiskScore = (score) => {
    if (typeof score === 'number') {
      return score.toFixed(1);
    } else if (score !== undefined && score !== null && !isNaN(parseFloat(score))) {
      return parseFloat(score).toFixed(1);
    } else {
      return "N/A";
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <h2 className="text-2xl font-bold tracking-tight">Dashboard Overview</h2>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        {/* Overview Stats */}
        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Logins</CardTitle>
            <BarChart3 className="h-4 w-4 text-teal-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.totalLogins || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.loginChange !== undefined
                ? `${stats.loginChange > 0 ? '+' : ''}${stats.loginChange}`
                : '0'}% from last month
            </p>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
            <Shield className="h-4 w-4 text-teal-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.securityScore || 0}%</div>
            <div className="mt-2">
              <Progress value={stats?.securityScore || 0} className="h-2" />
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Based on security key adoption
            </p>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Successful Logins</CardTitle>
            <Bell className="h-4 w-4 text-teal-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.successRate || 0}%</div>
            <div className="mt-2 flex gap-2">
              <Badge
                variant="outline"
                className={`text-xs ${
                  stats?.successRate !== undefined ? (
                    stats.successRate >= 90
                      ? 'bg-green-50 text-green-700 border-green-200'
                      : stats.successRate >= 70
                      ? 'bg-amber-50 text-amber-700 border-amber-200'
                      : 'bg-red-50 text-red-700 border-red-200'
                  ) : 'bg-gray-50 text-gray-700 border-gray-200'
                }`}
              >
                {stats?.successRate !== undefined ? (
                  stats.successRate >= 90 ? 'High' : stats.successRate >= 70 ? 'Medium' : 'Low'
                ) : 'N/A'}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed Attempts</CardTitle>
            <ArrowDownRight className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.failedAttempts || 0}</div>
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
          <CardHeader>
            <CardTitle>Login Attempts</CardTitle>
            <CardDescription>Daily login attempts this month</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ChartErrorBoundary>
              {isLoading ? (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  Loading login attempts data...
                </div>
              ) : error ? (
                <div className="h-full flex items-center justify-center text-red-500">
                  {error}
                </div>
              ) : loginAttempts.length === 0 ? (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  No login attempts data available
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                   <LineChart
                    data={loginAttempts.length > 0 ? loginAttempts : [{ name: 'No data', successful: 0, failed: 0 }]}
                    margin={{
                    top: 10,
                    right: 10,
                    left: 10,
                    bottom: 0
                  }}
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
                   tickFormatter={(value: number) => Math.round(value).toString()}
                   allowDecimals={false}
                   domain={[0, 'auto']}
                />
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <Legend
                  verticalAlign="top"
                  height={36}
                  align="center"
                  iconType="circle"
                />
                <Line
                   type="monotone"
                   dataKey="successful"
                   stroke="#16A34A"
                   strokeWidth={2}
                   dot={true}
                   activeDot={{ r: 6 }}
                   connectNulls={true}
                   name="Successfully Logged In"
                   isAnimationActive={false}
                />
                <Tooltip
                   formatter={(value: number) => [
                     value.toString(),
                     "Attempts"
                   ]}
                   labelFormatter={(label: string) => `${label}`}
                 />
                <Line
                   type="monotone"
                   dataKey="failed"
                   stroke="#DC2626"
                   strokeWidth={2}
                   dot={true}
                   activeDot={{ r: 6 }}
                   connectNulls={true}
                   name="Failed to Login"
                   isAnimationActive={false}
                />
                  </LineChart>
                </ResponsiveContainer>
              )}
              </ChartErrorBoundary>
            </div>
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
                      Loading risk score data...
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
                            // Ensure riskScore is a number
                            riskScore: typeof item.riskScore === 'number' ? item.riskScore :
                                !isNaN(parseFloat(item.riskScore)) ? parseFloat(item.riskScore) : 0
                          })) : [{ name: 'No data', riskScore: 0, attemptCount: 0 }]}
                          margin={{
                            top: 5,
                            right: 10,
                            left: 10,
                            bottom: 0,
                          }}
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
                            tickFormatter={(value: number) => value.toString()}
                            allowDecimals={false}
                            domain={[0, 100]}
                            ticks={[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]}
                            interval={0}
                        />
                        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                        <Bar
                            dataKey="riskScore"
                            name="Risk Score"
                            isAnimationActive={false}
                            radius={[4, 4, 0, 0]}
                            activeBar={{ fill: 'none' }}
                        >
                          {(riskTrend || []).map((entry, index) => (
                              <Cell
                                  key={`cell-${index}`}
                                  fill={getRiskColor(typeof entry.riskScore === 'number' ? entry.riskScore :
                                      !isNaN(parseFloat(entry.riskScore)) ? parseFloat(entry.riskScore) : 0)}
                              />
                          ))}
                        </Bar>
                        <Tooltip
                            formatter={(value: any) => [
                              formatRiskScore(value),
                              "Risk Score"
                            ]}
                            labelFormatter={(label: string) => `${label}`}
                            content={({ active, payload, label }) => {
                              if (active && payload && payload.length) {
                                const data = payload[0].payload;
                                return (
                                    <div className="bg-white p-2 border border-gray-200 shadow-md text-sm">
                                      <p className="font-bold">{label}</p>
                                      <p>Average Risk Score: {formatRiskScore(data.riskScore)}</p>
                                      <p>Login Attempts: {data.attemptCount || 0}</p>
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
            <div className="mt-4 flex justify-center space-x-4 text-xs text-muted-foreground">
              <div className="flex items-center">
                <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#16A34A' }}></span>
                Low Risk (&lt;=40)
              </div>
              <div className="flex items-center">
                <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#F59E0B' }}></span>
                Medium Risk (41-75)
              </div>
              <div className="flex items-center">
                <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#DC2626' }}></span>
                High Risk (&gt;75)
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        {/* Security Score Distribution */}
        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle>Security Metrics</CardTitle>
            <CardDescription>Distribution of security measures</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                  <Pie
                    data={securityMetrics}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                  >
                    {securityMetrics.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={index === 0 ? "#16A34A" : "#DC2626"}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, name) => [`${value} users`, name]}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                  />
                </PieChart>
              </ResponsiveContainer>
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
                   >
                     {deviceStats.map((entry, index) => (
                       <Cell
                         key={`cell-${index}`}
                         fill={[
                           "#16A34A", // Windows/Desktop - Green
                           "#F59E0B", // Mobile - Amber
                           "#3B82F6", // Tablet - Blue
                           "#8B5CF6", // Mac - Purple
                           "#EC4899", // Linux - Pink
                           "#6B7280"  // Others - Gray
                         ][index % 6]}
                       />
                     ))}
                   </Pie>
                   <Tooltip
                     formatter={(value: number) => [`${value} attempts`, "Logins"]}
                   />
                   <Legend
                     verticalAlign="bottom"
                     height={36}
                   />
                 </PieChart>
               </ResponsiveContainer>
             )}
             </ChartErrorBoundary>
           </div>
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
                       tickFormatter={(value: number) => Math.round(value).toString()}
                     />
                     <CartesianGrid strokeDasharray="3 3" />
                     <Bar dataKey="value" name="Attempts">
                       {locationStats.map((entry, index) => (
                         <Cell
                           key={`cell-${index}`}
                           fill={entry.severity === 'high'
                             ? '#DC2626'
                             : entry.severity === 'medium'
                             ? '#F59E0B'
                             : '#16A34A'
                           }
                         />
                       ))}
                     </Bar>
                     <Tooltip
                       formatter={(value: number) => [`${value} attempts`, 'Count']}
                     />
                   </BarChart>
                 </ResponsiveContainer>
               )}
             </ChartErrorBoundary>
           </div>
           {/* Custom Legend for Severity Colors */}
           <div className="mt-4 flex justify-center space-x-4 text-xs text-muted-foreground">
             <div className="flex items-center">
               <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#16A34A' }}></span>
               Low (&lt;=5)
             </div>
             <div className="flex items-center">
               <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#F59E0B' }}></span>
               Medium (6-15)
             </div>
             <div className="flex items-center">
               <span className="w-3 h-3 rounded-sm mr-1.5" style={{ backgroundColor: '#DC2626' }}></span>
               High (&gt;15)
             </div>
           </div>
         </CardContent>
       </Card>
      </div>
    </div>
  )
}
