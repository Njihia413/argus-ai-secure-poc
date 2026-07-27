"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { securityKeysColumns } from "@/components/data-table/security-keys-columns"
import { useEffect, useState, useMemo } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import { useAuthStore } from "@/store/auth"
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
  device_type: string | null
  form_factor: string | null
  serialNumber: string | null
  version: string | null
  status: "active" | "inactive" // Simplified as per feedback
  registeredOn: string // ISO date string
  lastUsed: string // ISO date string or "Never"
  username: string // Added username
}

export default function SecurityKeysPage() {
  const { user: authUser, _hasHydrated } = useAuthStore()
  const authToken = authUser?.authToken ?? null
  const [data, setData] = useState<SecurityKey[]>([])
  const [loading, setLoading] = useState(true)
  const [pageCount, setPageCount] = useState(0)
  const [total, setTotal] = useState(0)
  const [perPage, setPerPage] = useState(0)
  const router = useRouter()
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = useState({})
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 50,
  })
  const [statusFilterValue, setStatusFilterValue] = useState<string>("all")
  const [searchFilter, setSearchFilter] = useState("")

  const filteredData = useMemo(() => {
    return data.filter(key => {
      if (statusFilterValue !== "all" && key.status !== statusFilterValue) return false
      const searchTerm = searchFilter.toLowerCase()
      if (!searchTerm) return true
      return (
        (key.device_type && key.device_type.toLowerCase().includes(searchTerm)) ||
        (key.form_factor && key.form_factor.toLowerCase().includes(searchTerm)) ||
        (key.serialNumber && key.serialNumber.toLowerCase().includes(searchTerm)) ||
        (key.version && key.version.toLowerCase().includes(searchTerm)) ||
        key.username.toLowerCase().includes(searchTerm)
      )
    })
  }, [data, statusFilterValue, searchFilter])

  useEffect(() => {
    if (!_hasHydrated) return
    if (!authToken) {
      router.push("/")
      return
    }

    if (authUser?.role !== "admin") {
      toast.error("Admin access required to view all security keys.")
      router.push("/dashboard")
      return
    }

    fetchSecurityKeys(authToken)
  }, [authToken, authUser?.role, router, pagination, _hasHydrated])

  const refreshData = () => {
    if (authToken) {
      fetchSecurityKeys(authToken);
    }
  };

  const fetchSecurityKeys = async (authToken: string) => {
    setLoading(true)
    try {
      const response = await axios.get<{ securityKeys: SecurityKey[]; page: number; pages: number; per_page: number; total: number }>(
        `${API_URL}/security-keys/all?page=${pagination.pageIndex + 1}`,
        { headers: { Authorization: `Bearer ${authToken}` } },
      )
      if (response.data && response.data.securityKeys) {
        setData(response.data.securityKeys)
        setPageCount(response.data.pages)
        setTotal(response.data.total)
        setPerPage(response.data.per_page)
      } else {
        toast.error("Invalid data format received from server for security keys.")
      }
    } catch (error: any) {
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
            <>
            {total > 0 && (
              <p className="text-xs text-muted-foreground mb-3">
                Showing {pagination.pageIndex * perPage + 1}–{pagination.pageIndex * perPage + filteredData.length} of {total} keys
              </p>
            )}
            <DataTable
              columns={securityKeysColumns}
              data={filteredData}
              pageCount={pageCount}
              meta={{
                refreshData
              }}
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
                    placeholder="Search..."
                    value={searchFilter}
                    onChange={(event) =>
                      setSearchFilter(event.target.value)
                    }
                    className="max-w-sm bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                  />
                  <Select
                    value={statusFilterValue}
                    onValueChange={(value) => {
                      setStatusFilterValue(value)
                    }}
                  >
                    <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
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
                    <Button variant="outline" className="ml-auto bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-3xl text-foreground hover:bg-transparent">
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
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}