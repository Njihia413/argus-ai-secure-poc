"use client"

import { AlertTriangle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardFooter, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"

// Sample data for security alerts
const securityAlertsData = [
  {
    id: 1,
    type: "High Risk Login",
    user: "james_s",
    details: "Login attempt from unrecognized location in Beijing",
    time: "4 minutes ago",
    severity: "High",
  },
  {
    id: 2,
    type: "Multiple Failed Attempts",
    user: "guest123",
    details: "5 failed login attempts within 2 minutes",
    time: "35 minutes ago",
    severity: "Medium",
  },
  {
    id: 3,
    type: "Security Key Issue",
    user: "mike_l",
    details: "Authentication counter regression detected",
    time: "2 hours ago",
    severity: "High",
  },
  {
    id: 4,
    type: "Account Lockout",
    user: "test_user",
    details: "Account locked after multiple failed attempts",
    time: "Yesterday",
    severity: "Medium",
  },
  {
    id: 5,
    type: "Password Reset",
    user: "emma_d",
    details: "Password changed from new device",
    time: "2 days ago",
    severity: "Low",
  },
]

export default function SecurityPage() {
  return (
    <div className="grid gap-6">
      <h2 className="text-2xl font-bold tracking-tight">Security Overview</h2>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle className="text-sm font-medium">All Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <div className="mt-2 flex gap-2">
              <Badge variant="destructive" className="text-xs">
                3 High
              </Badge>
              <Badge variant="outline" className="text-xs bg-amber-50 text-amber-700 border-amber-200">
                5 Medium
              </Badge>
              <Badge variant="outline" className="text-xs bg-teal-50 text-teal-700 border-teal-200">
                4 Low
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Security Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">85.2%</div>
            <p className="text-xs text-muted-foreground mt-2">+2.5% from last week</p>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24</div>
            <p className="text-xs text-muted-foreground mt-2">Across 12 unique devices</p>
          </CardContent>
        </Card>
      </div>

      <Card className="shadow-sm hover:shadow-md transition-shadow">
        <CardHeader>
          <CardTitle>Recent Security Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Details</TableHead>
                <TableHead>Time</TableHead>
                <TableHead>Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {securityAlertsData.map((alert) => (
                <TableRow key={alert.id}>
                  <TableCell className="font-medium">
                    <div className="flex items-center">
                      <AlertTriangle
                        className={`h-4 w-4 mr-2 ${
                          alert.severity === "High"
                            ? "text-red-500"
                            : alert.severity === "Medium"
                              ? "text-amber-500"
                              : "text-blue-500"
                        }`}
                      />
                      {alert.type}
                    </div>
                  </TableCell>
                  <TableCell>{alert.user}</TableCell>
                  <TableCell>{alert.details}</TableCell>
                  <TableCell>{alert.time}</TableCell>
                  <TableCell>
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
                          ? ""
                          : alert.severity === "Medium"
                            ? "bg-amber-50 text-amber-700 border-amber-200"
                            : "bg-blue-50 text-blue-700 border-blue-200"
                      }
                    >
                      {alert.severity}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
        <CardFooter className="border-t px-6 py-4 flex justify-between">
          <Button variant="outline">Export Report</Button>
          <Button className="bg-teal-600 hover:bg-teal-700">View All Alerts</Button>
        </CardFooter>
      </Card>
    </div>
  )
}