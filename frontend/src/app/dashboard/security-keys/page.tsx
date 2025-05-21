"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { SecurityKeysDataTable } from "@/components/data-table/security-keys-data-table"
import { securityKeysColumns } from "@/components/data-table/security-keys-columns"
import { useEffect, useState } from "react"

// Placeholder data - replace with actual data fetching
export interface SecurityKey { // Exporting for use in columns file if needed, though it's defined there too
  id: string
  model: string
  type: string
  serialNumber: string
  status: "active" | "inactive" | "revoked"
  registeredOn: string // Should be a date
  lastUsed: string // Should be a date or "Never"
}

const mockSecurityKeys: SecurityKey[] = [
  { id: "1", model: "YubiKey 5C NFC", type: "USB-C/NFC", serialNumber: "YK12345678", status: "active", registeredOn: "2023-01-15", lastUsed: "2023-05-20" },
  { id: "2", model: "Google Titan Key", type: "USB-A/NFC/BLE", serialNumber: "GT98765432", status: "inactive", registeredOn: "2022-11-01", lastUsed: "2023-03-10" },
  { id: "3", model: "SoloKey v2", type: "USB-A", serialNumber: "SK24681357", status: "active", registeredOn: "2023-03-22", lastUsed: "Never" },
  { id: "4", model: "YubiKey Bio", type: "USB-A/Biometric", serialNumber: "YKBIO11223", status: "revoked", registeredOn: "2021-07-30", lastUsed: "2022-01-05" },
];

export default function SecurityKeysPage() {
  const [data, setData] = useState<SecurityKey[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate API call
    const fetchData = async () => {
      setLoading(true)
      // In a real app, you would fetch data from an API
      // For now, we use mock data with a delay
      await new Promise(resolve => setTimeout(resolve, 1000))
      setData(mockSecurityKeys)
      setLoading(false)
    }
    fetchData()
  }, [])

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