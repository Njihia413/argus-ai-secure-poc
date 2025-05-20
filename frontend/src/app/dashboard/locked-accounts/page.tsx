'use client'

import { Card } from "@/components/ui/card"
import { LockedAccountsDataTable } from "../../../components/data-table/locked-accounts-data-table"

export default function LockedAccountsPage() {
  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">Locked Accounts</h2>
      </div>
      <div className="grid gap-4">
        <Card className="col-span-4">
          <LockedAccountsDataTable />
        </Card>
      </div>
    </div>
  )
}