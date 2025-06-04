"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import axios from "axios"
import { toast } from "sonner"
import { API_URL } from "@/app/utils/constants"
import {
  ColumnDef,
  ColumnFiltersState,
  SortingState,
  VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table"
import { 
  ArrowUpDown, 
  ChevronDown, 
  ChevronLeft,
  ChevronRight, 
  MoreHorizontal, 
  UserPlus 
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"

interface User {
  id: number;
  nationalId: string;
  username: string;
  firstName: string;
  middlename: string | null;
  lastName: string;
  email: string;
  role: string;
  lastLogin: string | null;
}

export type RecentUser = {
  id: number;
  nationalId: string;
  username: string;
  firstName: string;
  middlename: string | null;
  lastName: string;
  email: string;
  role: string;
};

export const columns: ColumnDef<RecentUser>[] = [
  {
    id: "select",
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllPageRowsSelected() ||
          (table.getIsSomePageRowsSelected() && "indeterminate")
        }
        onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
        aria-label="Select all"
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        onCheckedChange={(value) => row.toggleSelected(!!value)}
        aria-label="Select row"
      />
    ),
    enableSorting: false,
    enableHiding: false,
  },
  {
    id: "fullName",
    header: ({ column }) => (
      <Button
        variant="ghost"
        onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
      >
        Full Name
        <ArrowUpDown className="ml-2 h-4 w-4" />
      </Button>
    ),
    cell: ({ row }) => (
      <div className="font-medium">
        {row.original.firstName} {row.original.middlename ? row.original.middlename + ' ' : ''}{row.original.lastName}
      </div>
    ),
  },
  {
    accessorKey: "nationalId",
    header: "National ID",
    cell: ({ row }) => <div>{row.getValue("nationalId")}</div>,
  },
  {
    accessorKey: "email",
    header: ({ column }) => (
      <Button
        variant="ghost"
        onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
      >
        Email
        <ArrowUpDown className="ml-2 h-4 w-4" />
      </Button>
    ),
    cell: ({ row }) => <div className="lowercase">{row.getValue("email")}</div>,
  },
  {
    accessorKey: "role",
    header: "Role",
    cell: ({ row }) => (
      <Badge variant="outline" className="capitalize">{row.getValue("role")}</Badge>
    ),
  },
  {
    id: "actions",
    enableHiding: false,
    cell: ({ row }) => {
      const user = row.original

      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0">
              <span className="sr-only">Open menu</span>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="rounded-xl font-montserrat">
            <DropdownMenuLabel className="font-normal">Actions</DropdownMenuLabel>
            <DropdownMenuSeparator className="rounded-md" />
            <DropdownMenuItem>View details</DropdownMenuItem>
            <DropdownMenuItem>Edit user</DropdownMenuItem>
            <DropdownMenuItem className="text-red-600">Delete user</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )
    },
  },
]

export function RecentUsersTable(): React.ReactElement {
  const [users, setUsers] = React.useState<RecentUser[]>([])
  const [sorting, setSorting] = React.useState<SortingState>([])
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = React.useState({})
  const [isLoading, setIsLoading] = React.useState(true)
  const [searchTerm, setSearchTerm] = React.useState("")
  const router = useRouter()

  React.useEffect(() => {
    const fetchUsers = async () => {
      try {
        const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
        if (!userInfo.authToken) {
          toast.error("Authentication required")
          return
        }

        const response = await axios.get<{ users: User[] }>(`${API_URL}/users`, {
          headers: {
            Authorization: `Bearer ${userInfo.authToken}`,
          },
        })

        if (response.data && response.data.users) {
          const sortedUsers = response.data.users
            .sort((a: User, b: User) => {
              const dateA = a.lastLogin ? new Date(a.lastLogin).getTime() : 0
              const dateB = b.lastLogin ? new Date(b.lastLogin).getTime() : 0
              return dateB - dateA
            })
            .slice(0, 5)
            .map((user: User): RecentUser => ({
              id: user.id,
              nationalId: user.nationalId,
              username: user.username,
              firstName: user.firstName,
              middlename: user.middlename,
              lastName: user.lastName,
              email: user.email,
              role: user.role,
            }))

          setUsers(sortedUsers)
        }
      } catch (error: any) {
        console.error("Error fetching users:", error.response?.data || error.message)
        toast.error(error.response?.data?.error || "Failed to load users data")
      } finally {
        setIsLoading(false)
      }
    }

    fetchUsers()
  }, [])

  const filteredData = React.useMemo(() => {
    const term = searchTerm.toLowerCase()
    return users.filter((user: RecentUser) => {
      const fullName = `${user.firstName} ${user.middlename ? user.middlename + ' ' : ''}${user.lastName}`.toLowerCase()
      return (
        fullName.includes(term) ||
        user.email.toLowerCase().includes(term) ||
        user.role.toLowerCase().includes(term)
      )
    })
  }, [users, searchTerm])

  const table = useReactTable({
    data: filteredData,
    columns,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
  })

  return (
    <Card className="shadow-sm hover:shadow-md transition-shadow">
      <CardHeader>
        <div className="flex justify-between items-center">
          <div>
            <CardTitle>Recent Users</CardTitle>
            {/* <CardDescription>Latest 5 users in the system</CardDescription> */}
          </div>
          <Button
            variant="outline"
            onClick={() => router.push('/dashboard/users')}
            className="bg-input border border-[var(--border)] rounded-3xl"
          >
            View all users <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
            <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
            <span>Loading users...</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center py-4">
              <Input
                placeholder="Search users..."
                value={searchTerm}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) => setSearchTerm(event.target.value)}
                className="max-w-sm"
              />
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" className="ml-auto bg-input border border-[var(--border)] rounded-3xl">
                    Columns <ChevronDown className="ml-2 h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="rounded-xl">
                  {table
                    .getAllColumns()
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
                        {column.id === "fullName" ? "Full Name" : column.id}
                      </DropdownMenuCheckboxItem>
                    ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
            <div className="rounded-md border border-[var(--card-border-themed)]">
              <Table>
                <TableHeader>
                  {table.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <TableHead key={header.id}>
                          {header.isPlaceholder
                            ? null
                            : flexRender(
                                header.column.columnDef.header,
                                header.getContext()
                              )}
                        </TableHead>
                      ))}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody>
                  {table.getRowModel().rows?.length ? (
                    table.getRowModel().rows.map((row) => (
                      <TableRow
                        key={row.id}
                        data-state={row.getIsSelected() && "selected"}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id}>
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext()
                            )}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell
                        colSpan={columns.length}
                        className="h-24 text-center"
                      >
                        No results.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
            <div className="flex items-center justify-end space-x-2 py-4">
              <div className="flex-1 text-sm text-muted-foreground">
                {table.getFilteredSelectedRowModel().rows.length} of{" "}
                {table.getFilteredRowModel().rows.length} row(s) selected.
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8 p-0 border-[var(--card-border-themed)]"
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span className="sr-only">Previous page</span>
                </Button>
                <Button
                  variant="outline"
                  size="icon"
                  className="h-8 w-8 p-0 border-[var(--card-border-themed)]"
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                >
                  <ChevronRight className="h-4 w-4" />
                  <span className="sr-only">Next page</span>
                </Button>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
