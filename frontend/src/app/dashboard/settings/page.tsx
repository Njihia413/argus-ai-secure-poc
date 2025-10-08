"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
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
import { Switch } from "@/components/ui/switch"
import { API_URL } from "@/app/utils/constants"
import { toast } from "sonner"
import axios from "axios"
import { Loader2 } from "lucide-react"

interface Settings {
  session_timeout: number
  failed_login_attempts: number
  webauthn_timeout: number
  min_password_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_numbers: boolean
  require_special_chars: boolean
  password_expiry_days: number
  updated_by: string | null
  updated_at: string | null
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [originalSettings, setOriginalSettings] = useState<Settings | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [isResetting, setIsResetting] = useState(false)
  const router = useRouter()

  // Check if settings have changed
  const hasChanges = originalSettings && settings 
    ? JSON.stringify(originalSettings) !== JSON.stringify(settings)
    : false

  // Handle authentication errors
  const handleAuthError = (error: any) => {
    if (error.response?.status === 401) {
      toast.error('Session expired. Please log in again.')
      sessionStorage.clear()
      localStorage.clear()
      router.push('/')
      return true
    }
    return false
  }

  // Fetch current settings
  const fetchSettings = async () => {
    setIsLoading(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      const response = await axios.get<Settings>(`${API_URL}/settings`, {
        headers: { Authorization: `Bearer ${userInfo.authToken}` }
      })
      setSettings(response.data)
      setOriginalSettings(response.data)
    } catch (error: any) {
      console.log('Error fetching settings:', error)
      if (!handleAuthError(error)) {
        toast.error('Failed to load settings')
      }
    } finally {
      setIsLoading(false)
    }
  }

  // Save settings
  const saveSettings = async () => {
    if (!settings) return

    setIsSaving(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.post(`${API_URL}/settings`, settings, {
        headers: { Authorization: `Bearer ${userInfo.authToken}` }
      })
      toast.success('Settings saved successfully')
      setOriginalSettings(settings)
    } catch (error: any) {
      console.log('Error saving settings:', error)
      if (!handleAuthError(error)) {
        toast.error(error.response?.data?.error || 'Failed to save settings')
      }
    } finally {
      setIsSaving(false)
    }
  }

  // Reset to defaults
  const resetToDefaults = async () => {
    setIsResetting(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.post(`${API_URL}/settings/reset`, {}, {
        headers: { Authorization: `Bearer ${userInfo.authToken}` }
      })
      toast.success('Settings reset to defaults')
      await fetchSettings() // Reload settings after reset
    } catch (error: any) {
      console.log('Error resetting settings:', error)
      if (!handleAuthError(error)) {
        toast.error(error.response?.data?.error || 'Failed to reset settings')
      }
    } finally {
      setIsResetting(false)
    }
  }

  // Update a specific setting
  const updateSetting = (key: keyof Settings, value: string | number | boolean) => {
    if (!settings) return
    setSettings({ ...settings, [key]: value })
  }

  useEffect(() => {
    fetchSettings()
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <p>Failed to load settings</p>
      </div>
    )
  }

  return (
    <>
      <div className="flex justify-between items-center bg-background px-4 py-4 sticky top-0 z-40">
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <div className="flex space-x-4">
          <Button 
            variant="outline" 
            onClick={resetToDefaults}
            disabled={isResetting || isSaving}
            className="border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950 dark:hover:text-red-300"
          >
            {isResetting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Resetting...
              </>
            ) : (
              'Reset to Defaults'
            )}
          </Button>
          <Button 
            onClick={saveSettings}
            disabled={!hasChanges || isSaving || isResetting}
            className="bg-blue-600 hover:bg-blue-700 text-white dark:bg-blue-600 dark:hover:bg-blue-700"
          >
            {isSaving ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              'Save Changes'
            )}
          </Button>
        </div>
      </div>

      <div className="px-4 py-6 space-y-8">
        <div className="grid gap-8">
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Security Settings</CardTitle>
              <p className="text-sm text-muted-foreground">
                Configure security policies that are actively enforced by the system
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label>Failed Login Attempts</Label>
                <p className="text-xs text-muted-foreground">Number of failed login attempts before account lockout</p>
                <Select 
                  value={settings.failed_login_attempts.toString()} 
                  onValueChange={(value) => updateSetting('failed_login_attempts', parseInt(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose attempt limit" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="3">3 attempts</SelectItem>
                    <SelectItem value="5">5 attempts</SelectItem>
                    <SelectItem value="7">7 attempts</SelectItem>
                    <SelectItem value="10">10 attempts</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Session Timeout (minutes)</Label>
                <p className="text-xs text-muted-foreground">How long user sessions remain active before requiring re-authentication</p>
                <Select 
                  value={settings.session_timeout.toString()} 
                  onValueChange={(value) => updateSetting('session_timeout', parseInt(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose timeout duration" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="5">5 minutes</SelectItem>
                    <SelectItem value="15">15 minutes</SelectItem>
                    <SelectItem value="30">30 minutes</SelectItem>
                    <SelectItem value="60">60 minutes</SelectItem>
                    <SelectItem value="120">120 minutes</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>WebAuthn Timeout (milliseconds)</Label>
                <p className="text-xs text-muted-foreground">Time limit for security key authentication requests</p>
                <Select 
                  value={settings.webauthn_timeout.toString()} 
                  onValueChange={(value) => updateSetting('webauthn_timeout', parseInt(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose timeout duration" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30000">30 seconds</SelectItem>
                    <SelectItem value="60000">60 seconds</SelectItem>
                    <SelectItem value="90000">90 seconds</SelectItem>
                    <SelectItem value="120000">120 seconds</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardHeader>
              <CardTitle>Password Policy</CardTitle>
              <p className="text-sm text-muted-foreground">
                Configure password requirements for new user accounts and password changes
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label>Minimum Password Length</Label>
                <p className="text-xs text-muted-foreground">Minimum number of characters required in passwords</p>
                <Select 
                  value={settings.min_password_length.toString()} 
                  onValueChange={(value) => updateSetting('min_password_length', parseInt(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose minimum length" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="6">6 characters</SelectItem>
                    <SelectItem value="8">8 characters</SelectItem>
                    <SelectItem value="10">10 characters</SelectItem>
                    <SelectItem value="12">12 characters</SelectItem>
                    <SelectItem value="16">16 characters</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Require Uppercase</Label>
                    <p className="text-xs text-muted-foreground">At least one uppercase letter (A-Z)</p>
                  </div>
                  <Switch
                    checked={settings.require_uppercase}
                    onCheckedChange={(checked) => updateSetting('require_uppercase', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Require Lowercase</Label>
                    <p className="text-xs text-muted-foreground">At least one lowercase letter (a-z)</p>
                  </div>
                  <Switch
                    checked={settings.require_lowercase}
                    onCheckedChange={(checked) => updateSetting('require_lowercase', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Require Numbers</Label>
                    <p className="text-xs text-muted-foreground">At least one numeric digit (0-9)</p>
                  </div>
                  <Switch
                    checked={settings.require_numbers}
                    onCheckedChange={(checked) => updateSetting('require_numbers', checked)}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Require Special Characters</Label>
                    <p className="text-xs text-muted-foreground">At least one special symbol (!@#$%^&*)</p>
                  </div>
                  <Switch
                    checked={settings.require_special_chars}
                    onCheckedChange={(checked) => updateSetting('require_special_chars', checked)}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Password Expiry (days)</Label>
                <p className="text-xs text-muted-foreground">How often users must change their passwords (0 = never expires)</p>
                <Select 
                  value={settings.password_expiry_days.toString()} 
                  onValueChange={(value) => updateSetting('password_expiry_days', parseInt(value))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose expiry period" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="0">Never expires</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="60">60 days</SelectItem>
                    <SelectItem value="90">90 days</SelectItem>
                    <SelectItem value="180">180 days</SelectItem>
                    <SelectItem value="365">365 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </div>

        {(settings.updated_by || settings.updated_at) && (
          <div className="text-sm text-muted-foreground text-center">
            Last updated by {settings.updated_by || 'Unknown'} 
            {settings.updated_at && ` on ${new Date(settings.updated_at).toLocaleString()}`}
          </div>
        )}
      </div>
    </>
  )
}