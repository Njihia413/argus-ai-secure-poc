"use client"

import { useState, useEffect } from "react"
import { useParams, useRouter } from "next/navigation"
import axios from "axios"
import { toast } from "sonner"
import { API_URL } from "@/app/utils/constants"
import { registerSecurityKey } from "@/app/utils/webauthn"
import { ArrowLeft, ChevronRight, Key, KeyRound } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

interface User {
  id: number
  username: string
  firstName: string
  lastName: string
  role: string
  hasSecurityKey: boolean
  lastLogin: string | null
  loginAttempts: number
  failedAttempts: number
}

export default function UserDetailsPage() {
  const router = useRouter()
  const params = useParams()
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [showRegistrationModal, setShowRegistrationModal] = useState(false)
  const [isRegistering, setIsRegistering] = useState(false)

  useEffect(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")

    if (!userInfo || !userInfo.authToken) {
      toast.error("You need to log in")
      router.push("/login")
      return
    }

    if (userInfo.role !== "admin") {
      toast.error("Admin access required")
      router.push("/")
      return
    }

    fetchUserDetails(userInfo.authToken)
  }, [router, params.id])

  const fetchUserDetails = async (authToken: string) => {
    try {
      setIsLoading(true)
      const response = await axios.get(`${API_URL}/users/${params.id}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })

      if (response.data && response.data.user) {
        setUser(response.data.user)
      } else {
        toast.error("User not found")
        router.push("/dashboard/users")
      }
    } catch (error: any) {
      console.error("Error fetching user details:", error)
      toast.error(error.response?.data?.error || "Failed to load user details")
      router.push("/dashboard/users")
    } finally {
      setIsLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-600"></div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  return (
    <div className="grid gap-6 w-full font-montserrat">
      <div className="flex justify-between items-center bg-white p-4">
        <div className="flex items-center text-sm text-gray-500">
          <span className="hover:text-gray-800 cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
          <ChevronRight className="h-4 w-4 mx-1" />
          <span className="hover:text-gray-800 cursor-pointer" onClick={() => router.push("/dashboard/users")}>Users</span>
          <ChevronRight className="h-4 w-4 mx-1" />
          <span className="text-gray-800">{user.firstName} {user.lastName}</span>
        </div>
        <Button
          onClick={() => router.push("/dashboard/users")}
          className="bg-black hover:bg-black/90 text-white"
        >
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Users
        </Button>
      </div>

      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle>{user.firstName} {user.lastName}'s Information</CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="grid gap-8">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>First Name</Label>
                <Input value={user.firstName} disabled />
              </div>
              <div className="space-y-2">
                <Label>Last Name</Label>
                <Input value={user.lastName} disabled />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Username</Label>
                <Input value={user.username} disabled />
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <Input value={user.role} disabled />
              </div>
            </div>

            <div>
              <Label>Last Login</Label>
              <Input 
                value={user.lastLogin 
                  ? new Date(user.lastLogin).toLocaleString('en-US', {
                      dateStyle: 'medium',
                      timeStyle: 'short'
                    })
                  : 'Not available'
                } 
                disabled
                className="mb-4" 
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Successful Login Attempts</Label>
                <Input value={user.loginAttempts} disabled />
              </div>
              <div className="space-y-2">
                <Label>Failed Login Attempts</Label>
                <Input value={user.failedAttempts} disabled />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Security Key Status</Label>
              <div className="space-y-2">
                <div>
                  {user.hasSecurityKey ? (
                    <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                      Registered
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="bg-amber-50 text-amber-700 border-amber-200">
                      Not Registered
                    </Badge>
                  )}
                </div>
                {!user.hasSecurityKey && (
                  <Button
                    className="bg-black hover:bg-black/90 text-white"
                    onClick={() => setShowRegistrationModal(true)}
                  >
                    <Key className="h-4 w-4 mr-1" />
                    Register Security Key
                  </Button>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
      {/* Security Key Registration Modal */}
      <Dialog open={showRegistrationModal} onOpenChange={setShowRegistrationModal}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>Enhance Account Security</DialogTitle>
            <DialogDescription>
              Add a security key to protect {user.firstName} {user.lastName}'s account against unauthorized access
              and phishing attacks.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div className="p-3 bg-amber-50 rounded-md border border-amber-200">
              <h3 className="text-amber-800 font-medium">Why Use a Security Key?</h3>
              <p className="text-amber-700 text-sm mt-1">
                Security keys provide significantly stronger protection than
                passwords alone. Even if the password is compromised, attackers
                cannot access the account without the physical security key.
              </p>
            </div>
            <div className="space-y-2 text-sm">
              <div className="p-3 bg-blue-50 rounded-md">
                <h4 className="font-medium text-blue-800">Compatible Devices</h4>
                <p className="text-blue-700 mt-1">
                  YubiKeys, Google Titan Security Keys, and most FIDO2-compatible
                  security keys
                </p>
              </div>
            </div>
          </div>

          <div className="flex justify-end space-x-4">
            <Button
              variant="outline"
              onClick={() => setShowRegistrationModal(false)}
              disabled={isRegistering}
              className="border-black bg-white hover:bg-gray-50"
            >
              Cancel
            </Button>
            <Button
              onClick={async () => {
                setIsRegistering(true)
                try {
                  await registerSecurityKey(
                    user.username,
                    async (message) => {
                      toast.success(message)
                      setShowRegistrationModal(false)
                      // Refresh user details to update security key status
                      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
                      await fetchUserDetails(userInfo.authToken)
                    },
                    (error) => {
                      toast.error(error)
                    }
                  )
                } finally {
                  setIsRegistering(false)
                }
              }}
              disabled={isRegistering}
              className="bg-black hover:bg-black/90 text-white"
            >
              {isRegistering ? (
                <>
                  <span className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></span>
                  Registering...
                </>
              ) : (
                <>
                  <KeyRound className="h-4 w-4 mr-1" />
                  Register Security Key
                </>
              )}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}