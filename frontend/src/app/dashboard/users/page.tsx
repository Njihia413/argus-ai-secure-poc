"use client"

import { useState, useEffect, useMemo } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import { CirclePlus, Eye, EyeOff, LockOpen, ChevronDown } from "lucide-react"
import {
  ColumnFiltersState,
  SortingState,
  VisibilityState,
} from "@tanstack/react-table"
import axios from "axios"
import { toast } from "sonner"
import { DataTable } from "@/components/data-table/data-table"
import { columns } from "@/components/data-table/columns"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

// User type definition
interface User {
  id: number
  nationalId: string
  username: string
  firstName: string
  middlename: string | null
  lastName: string
  email: string
  role: string
  hasSecurityKey: boolean
  securityKeyStatus: string | null
  lastLogin: string | null
  account_locked: boolean
}

// New user form interface
interface UserFormData {
  firstName: string
  middlename: string
  lastName: string
  nationalId: string
  username: string
  email: string
  password: string
  role: string
}

// Edit user form interface
interface EditUserFormData {
  firstName: string
  middlename: string
  lastName: string
  nationalId: string
  username: string
  email: string
  role: string
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()

  // Dialog states
  const [isAddUserDialogOpen, setIsAddUserDialogOpen] = useState(false)
  const [isEditUserDialogOpen, setIsEditUserDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [isUnlockAccountDialogOpen, setIsUnlockAccountDialogOpen] = useState(false)

  // Table states
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = useState({})
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  })
  const [pageCount, setPageCount] = useState(0)

  // Filter states
  const [searchFilter, setSearchFilter] = useState("")
  const [roleFilter, setRoleFilter] = useState("all")
  const [securityKeyFilter, setSecurityKeyFilter] = useState("all")
  const [accountStatusFilter, setAccountStatusFilter] = useState("all")

  // New user form state
  const [newUserForm, setNewUserForm] = useState<UserFormData>({
    firstName: "",
    middlename: "",
    lastName: "",
    nationalId: "",
    username: "",
    email: "",
    password: "",
    role: "user",
  })
  const [editUserForm, setEditUserForm] = useState<EditUserFormData>({
    firstName: "",
    middlename: "",
    lastName: "",
    nationalId: "",
    username: "",
    email: "",
    role: "user",
  })
  const [showPassword, setShowPassword] = useState(false)

  const fetchUsers = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      if (!userInfo || !userInfo.authToken) {
        toast.error("You need to log in")
        router.push("/")
        return
      }
      if (userInfo.role !== "admin") {
        toast.error("Admin access required")
        router.push("/")
        return
      }

      const response = await axios.get<{ users: User[] }>(`${API_URL}/users`, {
        headers: { Authorization: `Bearer ${userInfo.authToken}` },
      })

      if (response.data && response.data.users) {
        setUsers(response.data.users)
      } else {
        throw new Error("Invalid data format received from server")
      }
    } catch (error: any) {
      console.error("Error fetching users:", error.response?.data || error.message)
      toast.error(error.response?.data?.error || "Failed to load users.")
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [router])

  useEffect(() => {
    if (selectedUser) {
      setEditUserForm({
        firstName: selectedUser.firstName,
        middlename: selectedUser.middlename || "",
        lastName: selectedUser.lastName,
        nationalId: selectedUser.nationalId,
        username: selectedUser.username,
        email: selectedUser.email,
        role: selectedUser.role,
      })
    }
  }, [selectedUser])

  useEffect(() => {
    if (selectedUser) {
      setEditUserForm({
        firstName: selectedUser.firstName,
        middlename: selectedUser.middlename || "",
        lastName: selectedUser.lastName,
        nationalId: selectedUser.nationalId,
        username: selectedUser.username,
        email: selectedUser.email,
        role: selectedUser.role,
      })
    }
  }, [selectedUser])

  const filteredUsers = useMemo(() => {
    return users.filter(user => {
      if (roleFilter !== "all" && user.role !== roleFilter) return false
      if (securityKeyFilter !== "all") {
        if (securityKeyFilter === "none" && user.hasSecurityKey) return false
        if (securityKeyFilter === "active" && !(user.hasSecurityKey && user.securityKeyStatus === "active")) return false
        if (securityKeyFilter === "inactive" && !(user.hasSecurityKey && user.securityKeyStatus === "inactive")) return false
      }
      if (accountStatusFilter !== "all") {
        if (accountStatusFilter === "locked" && !user.account_locked) return false
        if (accountStatusFilter === "unlocked" && user.account_locked) return false
      }
      const searchTerm = searchFilter.toLowerCase()
      return (
        user.username.toLowerCase().includes(searchTerm) ||
        user.firstName.toLowerCase().includes(searchTerm) ||
        user.lastName.toLowerCase().includes(searchTerm) ||
        user.email.toLowerCase().includes(searchTerm) ||
        String(user.nationalId).includes(searchTerm)
      )
    })
  }, [users, roleFilter, securityKeyFilter, accountStatusFilter, searchFilter])

  const paginatedUsers = useMemo(() => {
    const start = pagination.pageIndex * pagination.pageSize
    const end = start + pagination.pageSize
    return filteredUsers.slice(start, end)
  }, [filteredUsers, pagination])

  useEffect(() => {
    setPageCount(Math.ceil(filteredUsers.length / pagination.pageSize))
  }, [filteredUsers, pagination.pageSize])

  const handleNewUserInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setNewUserForm(prev => ({ ...prev, [name]: value }))
  }

  const handleEditUserInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setEditUserForm(prev => ({ ...prev, [name]: value }))
  }

  const handleEditRoleChange = (value: string) => {
    setEditUserForm(prev => ({ ...prev, role: value }))
  }

  const handleRoleChange = (value: string) => {
    setNewUserForm(prev => ({ ...prev, role: value }))
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      if (!userInfo.authToken) {
        throw new Error("Authentication required")
      }
      await axios.post(`${API_URL}/register`, newUserForm, {
        headers: { Authorization: `Bearer ${userInfo.authToken}` },
      })
      toast.success(`User ${newUserForm.username} created successfully`)
      setIsAddUserDialogOpen(false)
      fetchUsers() // Refetch users
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to create user")
    } finally {
      setIsLoading(false)
    }
  }

  const handleUnlockUserAccount = async () => {
    if (!selectedUser) return
    setIsLoading(true)
    try {
      const userStr = sessionStorage.getItem('user')
      if (!userStr) throw new Error('User not authenticated')
      const adminUserInfo = JSON.parse(userStr)
      const authToken = adminUserInfo.authToken
      await fetch(`${API_URL}/users/${selectedUser.id}/unlock`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
      })
      toast.success(`User account ${selectedUser.username} unlocked successfully`)
      setIsUnlockAccountDialogOpen(false)
      fetchUsers() // Refetch users
    } catch (error: any) {
      toast.error(error.message || "Failed to unlock account. Please try again.")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">Users</h2>
        <Button onClick={() => setIsAddUserDialogOpen(true)}>
          <CirclePlus className="h-4 w-4" /> Add User
        </Button>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>User Management</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
              <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
              <span>Loading users...</span>
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={paginatedUsers}
              pageCount={pageCount}
              meta={{
                setSelectedUser,
                setIsDeleteDialogOpen,
                setIsEditUserDialogOpen,
                setIsUnlockAccountDialogOpen,
              }}
              state={{
                sorting,
                columnFilters,
                columnVisibility,
                rowSelection,
                pagination,
              }}
              onSortingChange={setSorting}
              onColumnFiltersChange={setColumnFilters}
              onColumnVisibilityChange={setColumnVisibility}
              onRowSelectionChange={setRowSelection}
              onPaginationChange={setPagination}
              enableRowSelection={true}
              toolbar={(table) => (
                <div className="flex items-center space-x-4 w-full font-montserrat">
                  <Input
                    placeholder="Search users..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    className="max-w-sm"
                  />
                  <Select value={roleFilter} onValueChange={setRoleFilter}>
                    <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                      <SelectValue placeholder="Filter by role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="all">All Roles</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="user">User</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <Select value={securityKeyFilter} onValueChange={setSecurityKeyFilter}>
                    <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                      <SelectValue placeholder="Filter by Security Key" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="all">All Security Keys</SelectItem>
                        <SelectItem value="none">None</SelectItem>
                        <SelectItem value="active">Active</SelectItem>
                        <SelectItem value="inactive">Inactive</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <Select value={accountStatusFilter} onValueChange={setAccountStatusFilter}>
                    <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                      <SelectValue placeholder="Filter by Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="all">All Accounts</SelectItem>
                        <SelectItem value="locked">Locked</SelectItem>
                        <SelectItem value="unlocked">Unlocked</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" className="ml-auto bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-3xl text-foreground hover:bg-transparent">
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
              )}
            />
          )}
        </CardContent>
      </Card>

      {/* Add User Dialog */}
      <Dialog open={isAddUserDialogOpen} onOpenChange={setIsAddUserDialogOpen}>
        <DialogContent className="sm:max-w-[500px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Add New User</DialogTitle>
            <DialogDescription>Create a new user account with defined permissions.</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreateUser}>
            <div className="grid gap-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="firstName">First Name</Label>
                <Input id="firstName" name="firstName" value={newUserForm.firstName} onChange={handleNewUserInputChange} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="middlename">Middle Name</Label>
                <Input id="middlename" name="middlename" value={newUserForm.middlename} onChange={handleNewUserInputChange} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="lastName">Last Name</Label>
                <Input id="lastName" name="lastName" value={newUserForm.lastName} onChange={handleNewUserInputChange} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="nationalId">National ID</Label>
                <Input id="nationalId" name="nationalId" type="number" value={newUserForm.nationalId} onChange={handleNewUserInputChange} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input id="username" name="username" value={newUserForm.username} onChange={handleNewUserInputChange} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input id="email" name="email" type="email" value={newUserForm.email} onChange={handleNewUserInputChange} required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input id="password" name="password" type={showPassword ? "text" : "password"} value={newUserForm.password} onChange={handleNewUserInputChange} required />
                  <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2">
                    {showPassword ? <EyeOff className="h-4 w-4 text-gray-500" /> : <Eye className="h-4 w-4 text-gray-500" />}
                  </button>
                </div>
              </div>
              <div className="space-y-2 w-full">
                <Label htmlFor="role">Role</Label>
                <Select value={newUserForm.role} onValueChange={handleRoleChange}>
                  <SelectTrigger className="w-full border border-input">
                    <SelectValue placeholder="Select a role" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectLabel>Available Roles</SelectLabel>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="hr">HR</SelectItem>
                      <SelectItem value="manager">Manager</SelectItem>
                      <SelectItem value="it_department">IT Department</SelectItem>
                      <SelectItem value="customer_service">Customer Service</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => setIsAddUserDialogOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={isLoading}>{isLoading ? "Creating..." : "Create User"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={isEditUserDialogOpen} onOpenChange={setIsEditUserDialogOpen}>
        <DialogContent className="sm:max-w-[500px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>Update user account details.</DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <form onSubmit={async (e) => {
              e.preventDefault()
              setIsLoading(true)
              try {
                const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
                if (!userInfo.authToken) throw new Error("Authentication required")
                await axios.put(`${API_URL}/users/${selectedUser.id}`, editUserForm, {
                  headers: { Authorization: `Bearer ${userInfo.authToken}` },
                })
                toast.success("User details updated successfully")
                setIsEditUserDialogOpen(false)
                fetchUsers()
              } catch (error: any) {
                toast.error(error.response?.data?.error || "Failed to update user")
              } finally {
                setIsLoading(false)
              }
            }}>
              <div className="grid gap-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First Name</Label>
                  <Input id="firstName" name="firstName" value={editUserForm.firstName} onChange={handleEditUserInputChange} required />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="middlename">Middle Name</Label>
                  <Input id="middlename" name="middlename" value={editUserForm.middlename} onChange={handleEditUserInputChange} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input id="lastName" name="lastName" value={editUserForm.lastName} onChange={handleEditUserInputChange} required />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="nationalId">National ID</Label>
                  <Input id="nationalId" name="nationalId" type="number" value={editUserForm.nationalId} onChange={handleEditUserInputChange} required />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input id="username" name="username" value={editUserForm.username} onChange={handleEditUserInputChange} required />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" name="email" type="email" value={editUserForm.email} onChange={handleEditUserInputChange} required />
                </div>
                <div className="space-y-2 w-full">
                  <Label htmlFor="role">Role</Label>
                  <Select value={editUserForm.role} onValueChange={handleEditRoleChange}>
                    <SelectTrigger className="w-full border border-input">
                      <SelectValue placeholder="Select a role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>Available Roles</SelectLabel>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="user">User</SelectItem>
                        <SelectItem value="hr">HR</SelectItem>
                        <SelectItem value="manager">Manager</SelectItem>
                        <SelectItem value="it_department">IT Department</SelectItem>
                        <SelectItem value="customer_service">Customer Service</SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" type="button" onClick={() => setIsEditUserDialogOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={isLoading}>{isLoading ? "Updating..." : "Update User"}</Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Delete User Dialog */}
      <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <DialogContent className="sm:max-w-[400px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>Are you sure you want to delete this user? This action cannot be undone.</DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <div>
              <div className="py-4">
                <p>You are about to delete the user: <strong>{selectedUser.username}</strong></p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
                <Button variant="destructive" disabled={isLoading} onClick={async () => {
                  setIsLoading(true)
                  try {
                    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
                    if (!userInfo.authToken) throw new Error("Authentication required")
                    await axios.delete(`${API_URL}/delete-user/${selectedUser.id}`, {
                      headers: { Authorization: `Bearer ${userInfo.authToken}` },
                    })
                    toast.success("User deleted successfully")
                    setIsDeleteDialogOpen(false)
                    fetchUsers()
                  } catch (error: any) {
                    toast.error(error.response?.data?.error || "Failed to delete user")
                  } finally {
                    setIsLoading(false)
                  }
                }}>
                  {isLoading ? "Deleting..." : "Delete User"}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Unlock Account Dialog */}
      <Dialog open={isUnlockAccountDialogOpen} onOpenChange={setIsUnlockAccountDialogOpen}>
        <DialogContent className="sm:max-w-[425px] font-montserrat">
          <DialogHeader>
            <DialogTitle>Unlock User Account</DialogTitle>
            <DialogDescription>Are you sure you want to unlock this user's account?</DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <div>
              <div className="py-4">
                <p>You are about to unlock the account for: <strong>{selectedUser.username}</strong></p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsUnlockAccountDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleUnlockUserAccount} disabled={isLoading}>
                  {isLoading ? "Unlocking..." : "Unlock Account"}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
