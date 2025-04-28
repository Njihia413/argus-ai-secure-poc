"use client"

import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"

export default function SettingsPage() {
  return (
    <>
      <div className="flex justify-between items-center border-b bg-background px-4 py-4 sticky top-0 z-40">
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <div className="flex space-x-4">
          <Button variant="outline" className="border-black">Reset to Defaults</Button>
          <Button className="bg-black hover:bg-black/90 text-white">Save Changes</Button>
        </div>
      </div>

      <div className="px-4 py-4">
        <div className="grid gap-6 md:grid-cols-2">
        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle>Security Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Multi-Factor Authentication</Label>
              <Select defaultValue="yes">
                <SelectTrigger>
                  <SelectValue placeholder="Choose MFA setting" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="yes">Required for all users</SelectItem>
                  <SelectItem value="optional">Optional</SelectItem>
                  <SelectItem value="no">Disabled</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Session Timeout (minutes)</Label>
              <Select defaultValue="90">
                <SelectTrigger>
                  <SelectValue placeholder="Choose timeout duration" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30">30 minutes</SelectItem>
                  <SelectItem value="60">60 minutes</SelectItem>
                  <SelectItem value="90">90 minutes</SelectItem>
                  <SelectItem value="120">120 minutes</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Failed Login Attempts</Label>
              <Select defaultValue="5">
                <SelectTrigger>
                  <SelectValue placeholder="Choose attempt limit" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="3">3 attempts</SelectItem>
                  <SelectItem value="5">5 attempts</SelectItem>
                  <SelectItem value="10">10 attempts</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Lockout Duration (minutes)</Label>
              <Select defaultValue="15">
                <SelectTrigger>
                  <SelectValue placeholder="Choose lockout duration" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 minutes</SelectItem>
                  <SelectItem value="15">15 minutes</SelectItem>
                  <SelectItem value="30">30 minutes</SelectItem>
                  <SelectItem value="60">60 minutes</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-sm hover:shadow-md transition-shadow">
          <CardHeader>
            <CardTitle>Password Policy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Minimum Password Strength</Label>
              <Select defaultValue="medium">
                <SelectTrigger>
                  <SelectValue placeholder="Choose strength requirement" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="very-high">Very High</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Password Expiry</Label>
              <Select defaultValue="medium">
                <SelectTrigger>
                  <SelectValue placeholder="Choose expiry period" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30">30 days</SelectItem>
                  <SelectItem value="60">60 days</SelectItem>
                  <SelectItem value="90">90 days</SelectItem>
                  <SelectItem value="never">Never</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Password History</Label>
              <Select defaultValue="enabled">
                <SelectTrigger>
                  <SelectValue placeholder="Choose history setting" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="disabled">Disabled</SelectItem>
                  <SelectItem value="enabled">Last 5 passwords</SelectItem>
                  <SelectItem value="strict">Last 10 passwords</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="shadow-sm hover:shadow-md transition-shadow">
        <CardHeader>
          <CardTitle>WebAuthn Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Registration Timeout (ms)</Label>
            <Select defaultValue="60000">
              <SelectTrigger>
                <SelectValue placeholder="Choose timeout duration" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30000">30 seconds</SelectItem>
                <SelectItem value="60000">60 seconds</SelectItem>
                <SelectItem value="120000">120 seconds</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Authentication Type</Label>
            <Select defaultValue="preferred">
              <SelectTrigger>
                <SelectValue placeholder="Choose auth type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="required">Required</SelectItem>
                <SelectItem value="preferred">Preferred</SelectItem>
                <SelectItem value="optional">Optional</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>User Verification</Label>
            <Select defaultValue="none">
              <SelectTrigger>
                <SelectValue placeholder="Choose verification level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="required">Required</SelectItem>
                <SelectItem value="preferred">Preferred</SelectItem>
                <SelectItem value="none">None</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Authenticator Attachment</Label>
            <Select defaultValue="cross-platform">
              <SelectTrigger>
                <SelectValue placeholder="Choose attachment type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="platform">Platform</SelectItem>
                <SelectItem value="cross-platform">Cross-Platform</SelectItem>
                <SelectItem value="any">Any</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>
      </div>
    </>
  )
}