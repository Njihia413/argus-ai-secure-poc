"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { securityKeysColumns } from "@/components/data-table/security-keys-columns"
import { useEffect, useState } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import axios from "axios"
import { toast } from "sonner"
import { ChevronDown } from "lucide-react"
import { DataTable } from "@/components/data-table/data-table"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  ColumnFiltersState,
  SortingState,
  VisibilityState,
} from "@tanstack/react-table"


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
  const [pageCount, setPageCount] = useState(0)
  const router = useRouter()
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = useState({})
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  })
  const [statusFilterValue, setStatusFilterValue] = useState<string>("all")

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
  }, [router, pagination, statusFilterValue])

  const fetchSecurityKeys = async (authToken: string) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        page: (pagination.pageIndex + 1).toString(),
        per_page: pagination.pageSize.toString(),
        status: statusFilterValue,
      })
      const response = await axios.get<{ securityKeys: SecurityKey[], pages: number }>(`${API_URL}/security-keys/all?${params.toString()}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })
 
      if (response.data && response.data.securityKeys) {
        setData(response.data.securityKeys)
        setPageCount(response.data.pages)
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
          {loading ? (
            <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
              <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
              <span>Loading security keys...</span>
            </div>
          ) : (
            <DataTable
              columns={securityKeysColumns}
              data={data}
              pageCount={pageCount}
            state={{
              sorting,
              columnFilters,
              columnVisibility,
              rowSelection,
              pagination
            }}
            onSortingChange={setSorting}
            onColumnFiltersChange={setColumnFilters}
            onColumnVisibilityChange={setColumnVisibility}
            onRowSelectionChange={setRowSelection}
            onPaginationChange={setPagination}
            enableRowSelection={true}
            getPaginationRowModel={true}
            getSortedRowModel={true}
            getFilteredRowModel={true}
            toolbar={(table) => (
              <div className="flex items-center justify-between w-full font-montserrat">
                <div className="flex items-center space-x-4">
                  <Input
                    placeholder="Search security keys..."
                    value={(table?.getColumn("model")?.getFilterValue() as string) ?? ""}
                    onChange={(event) =>
                      table?.getColumn("model")?.setFilterValue(event.target.value)
                    }
                    className="max-w-sm dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                  />
                  <Select
                    value={statusFilterValue}
                    onValueChange={(value) => {
                      setStatusFilterValue(value)
                    }}
                  >
                    <SelectTrigger className="w-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                      <SelectValue placeholder="Filter by status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Statuses</SelectItem>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="inactive">Inactive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" className="dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                      Columns <ChevronDown className="ml-2 h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="rounded-xl">
                    {table
                      ?.getAllColumns()
                      .filter((column) => column.getCanHide())
                      .map((column) => (
                        <DropdownMenuCheckboxItem
                          key={column.id}
                          className="capitalize"
                          checked={column.getIsVisible()}
                          onCheckedChange={(value) =>
                            column.toggleVisibility(!!value)
                          }
                        >
                          {column.id}
                        </DropdownMenuCheckboxItem>
                      ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            )}
          />
          )}
        </CardContent>
      </Card>
    </div>
  )
}