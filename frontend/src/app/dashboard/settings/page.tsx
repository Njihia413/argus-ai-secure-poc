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
    <div className="grid gap-6">
      <h2 className="text-2xl font-bold tracking-tight">Settings</h2>

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
