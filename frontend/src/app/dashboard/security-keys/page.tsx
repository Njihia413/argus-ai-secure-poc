"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { SecurityKeysDataTable } from "@/components/data-table/security-keys-data-table"
import { securityKeysColumns } from "@/components/data-table/security-keys-columns"
import { useEffect, useState } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import axios from "axios"
import { toast } from "sonner"


export interface SecurityKey {
  id: string | number // Backend uses integer ID
  model: string | null
  type: string | null
  serialNumber: string | null
  status: "active" | "inactive" // Simplified as per feedback
  registeredOn: string // ISO date string
  lastUsed: string // ISO date string or "Never"
  username: string // Added username
}

export default function SecurityKeysPage() {
  const [data, setData] = useState<SecurityKey[]>([])
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  useEffect(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")

    if (!userInfo || !userInfo.authToken) {
      toast.error("You need to log in to view security keys.")
      router.push("/login")
      return
    }

    if (userInfo.role !== "admin") {
      toast.error("Admin access required to view all security keys.")
      router.push("/dashboard") // Or appropriate non-admin page
      return
    }
    
    fetchSecurityKeys(userInfo.authToken)
  }, [router])

  const fetchSecurityKeys = async (authToken: string) => {
    setLoading(true)
    try {
      const response = await axios.get<{ securityKeys: SecurityKey[] }>(`${API_URL}/security-keys/all`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })

      if (response.data && response.data.securityKeys) {
        setData(response.data.securityKeys)
      } else {
        console.error("Invalid response format for security keys:", response.data)
        toast.error("Invalid data format received from server for security keys.")
      }
    } catch (error: any) {
      console.error("Error fetching security keys:", error.response?.data || error.message)
      toast.error(error.response?.data?.error || "Failed to load security keys.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <Card>
        <CardHeader>
          <CardTitle>Security Keys</CardTitle>
          <CardDescription>
            Manage and monitor all registered security keys.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SecurityKeysDataTable columns={securityKeysColumns} data={data} loading={loading} />
        </CardContent>
      </Card>
    </div>
  )
}