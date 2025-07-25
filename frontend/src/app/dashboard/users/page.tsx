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
import { Card, CardContent } from "@/components/ui/card"

// User type definition for real API integration
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
  securityKeyStatus: string | null // Add this field
  lastLogin: string | null
  successfulLoginAttempts: number
  failedAttempts: number
  account_locked: boolean
}

// New user form interface for real API integration
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

export default function UsersPage() {
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isEditUserDialogOpen, setIsEditUserDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const [isUnlockAccountDialogOpen, setIsUnlockAccountDialogOpen] = useState(false)
  const router = useRouter()
  const [isAddUserDialogOpen, setIsAddUserDialogOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [users, setUsers] = useState<User[]>([])
  const [pageCount, setPageCount] = useState(0)
  const [searchFilter, setSearchFilter] = useState("")
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [rowSelection, setRowSelection] = useState({})
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  })
  const [roleFilter, setRoleFilter] = useState("all") // 'all', 'admin', 'user'
  const [securityKeyFilter, setSecurityKeyFilter] = useState("all") // 'all', 'none', 'active', 'inactive'
  const [accountStatusFilter, setAccountStatusFilter] = useState("all") // 'all', 'locked', 'unlocked'

  const filteredUsers = useMemo(() => {
    return users
      .filter(user => {
        if (roleFilter !== "all" && user.role !== roleFilter) {
          return false
        }
        if (securityKeyFilter !== "all") {
          if (securityKeyFilter === "none" && user.hasSecurityKey) {
            return false
          }
          if (
            securityKeyFilter === "active" &&
            !(user.hasSecurityKey && user.securityKeyStatus === "active")
          ) {
            return false
          }
          if (
            securityKeyFilter === "inactive" &&
            !(user.hasSecurityKey && user.securityKeyStatus === "inactive")
          ) {
            return false
          }
        }
        if (accountStatusFilter !== "all") {
          if (
            accountStatusFilter === "locked" &&
            !user.account_locked
          ) {
            return false
          }
          if (
            accountStatusFilter === "unlocked" &&
            user.account_locked
          ) {
            return false
          }
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
    if (filteredUsers.length > 0) {
      setPageCount(Math.ceil(filteredUsers.length / pagination.pageSize))
    }
  }, [filteredUsers, pagination.pageSize])

  useEffect(() => {
    const fetchUsers = async () => {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");

      if (!userInfo || !userInfo.authToken) {
        toast.error("You need to log in");
        router.push("/");
        return;
      }

      if (userInfo.role !== "admin") {
        toast.error("Admin access required");
        router.push("/");
        return;
      }

      try {
        setIsLoading(true);
        const response = await axios.get<{ users: User[] }>(
          `${API_URL}/users`,
          {
            headers: {
              Authorization: `Bearer ${userInfo.authToken}`,
            },
          }
        );

        if (response.data && response.data.users) {
          setUsers(response.data.users);
        } else {
          console.error("Invalid response format:", response.data);
          toast.error("Invalid data format received from server");
        }
      } catch (error: any) {
        console.error("Error fetching users:", error.response?.data || error.message);
        toast.error(error.response?.data?.error || "Failed to load users data");
      } finally {
        setIsLoading(false);
      }
    };

    fetchUsers();
  }, [router]);

  // New user form state and handlers
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
  const [showPassword, setShowPassword] = useState(false)

  const handleNewUserInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setNewUserForm({
      ...newUserForm,
      [name]: value,
    })
  }

  const handleRoleChange = (value: string) => {
    setNewUserForm({
      ...newUserForm,
      role: value,
    })
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")

      if (!userInfo.authToken) {
        toast.error("Authentication required")
        setIsLoading(false)
        return
      }

      // Create the user via API
      await axios.post(`${API_URL}/register`, newUserForm, {
        headers: {
          Authorization: `Bearer ${userInfo.authToken}`,
        },
      })

      toast.success(`User ${newUserForm.username} created successfully`)

      // Reset form
      setNewUserForm({
        firstName: "",
        middlename: "",
        lastName: "",
        nationalId: "",
        username: "",
        email: "",
        password: "",
        role: "user",
      })

      // Close dialog and refresh users
      setIsAddUserDialogOpen(false)
      // No need to call fetchUsers, useEffect will refetch
    } catch (error: any) {
      console.error("Error creating user:", error)
      toast.error(error.response?.data?.error || "Failed to create user")
    } finally {
      setIsLoading(false)
    }
  }


  const handleUnlockUserAccount = async () => {
    if (!selectedUser) return; // Ensure selectedUser is not null
    setIsLoading(true);
    try {
      const userStr = sessionStorage.getItem('user');
      if (!userStr) {
        throw new Error('User not authenticated');
      }
      
      const adminUserInfo = JSON.parse(userStr);
      const authToken = adminUserInfo.authToken;

      const response = await fetch(`${API_URL}/users/${selectedUser.id}/unlock`, {
        method: 'POST', // Corrected method
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to unlock account');
      }
      
      toast.success(`User account ${selectedUser.username} unlocked successfully`);
      setUsers(prevUsers =>
        prevUsers.map(user =>
          user.id === selectedUser.id ? { ...user, account_locked: false } : user
        )
      );
      setIsUnlockAccountDialogOpen(false); // Close dialog on success
    } catch (error) {
      console.error('Error unlocking account:', error);
      toast.error((error as Error).message || "Failed to unlock account. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
      <>
        <div className="flex justify-between items-center bg-background px-4 py-4 sticky top-0 z-40">
          <h2 className="text-2xl font-bold tracking-tight">Users</h2>
          <Button onClick={() => setIsAddUserDialogOpen(true)}>
            <CirclePlus className="h-4 w-4" />
            Add User
          </Button>
        </div>

        <div className="px-4 py-4">
          <Card>
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
        </div>

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
                  <Input
                      id="firstName"
                      name="firstName"
                      value={newUserForm.firstName}
                      onChange={handleNewUserInputChange}
                      required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="middlename">Middle Name</Label>
                  <Input
                      id="middlename"
                      name="middlename"
                      value={newUserForm.middlename}
                      onChange={handleNewUserInputChange}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                      id="lastName"
                      name="lastName"
                      value={newUserForm.lastName}
                      onChange={handleNewUserInputChange}
                      required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="nationalId">National ID</Label>
                  <Input
                      id="nationalId"
                      name="nationalId"
                      type="number"
                      value={newUserForm.nationalId}
                      onChange={handleNewUserInputChange}
                      required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                      id="username"
                      name="username"
                      value={newUserForm.username}
                      onChange={handleNewUserInputChange}
                      required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                      id="email"
                      name="email"
                      type="email"
                      value={newUserForm.email}
                      onChange={handleNewUserInputChange}
                      required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Input
                        id="password"
                        name="password"
                        type={showPassword ? "text" : "password"}
                        value={newUserForm.password}
                        onChange={handleNewUserInputChange}
                        required
                    />
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2"
                    >
                      {showPassword ? (
                          <EyeOff className="h-4 w-4 text-gray-500" />
                      ) : (
                          <Eye className="h-4 w-4 text-gray-500" />
                      )}
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
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" type="button" onClick={() => setIsAddUserDialogOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={isLoading}>
                  {isLoading ? "Creating..." : "Create User"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

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
                    if (!userInfo.authToken) {
                      toast.error("Authentication required")
                      setIsLoading(false)
                      return
                    }

                    // Update user via API
                    await axios.put(
                        `${API_URL}/users/${selectedUser.id}`,
                        {
                          firstName: selectedUser.firstName,
                          middlename: selectedUser.middlename,
                          lastName: selectedUser.lastName,
                          nationalId: selectedUser.nationalId,
                          username: selectedUser.username,
                          email: selectedUser.email,
                          role: selectedUser.role,
                        },
                        {
                          headers: {
                            Authorization: `Bearer ${userInfo.authToken}`,
                          },
                        }
                    )

                    toast.success("User details updated successfully")
                    setIsEditUserDialogOpen(false)
                    // No need to call fetchUsers, useEffect will refetch
                  } catch (error: any) {
                    console.error("Error updating user:", error)
                    toast.error(error.response?.data?.error || "Failed to update user")
                  } finally {
                    setIsLoading(false)
                  }
                }}>
                  <div className="grid gap-4 py-4">
                    <div className="space-y-2">
                      <Label htmlFor="edit-firstName">First Name</Label>
                      <Input
                          id="edit-firstName"
                          name="firstName"
                          value={selectedUser.firstName}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            firstName: e.target.value
                          })}
                          required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-middlename">Middle Name</Label>
                      <Input
                          id="edit-middlename"
                          name="middlename"
                          value={selectedUser.middlename || ""}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            middlename: e.target.value
                          })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-lastName">Last Name</Label>
                      <Input
                          id="edit-lastName"
                          name="lastName"
                          value={selectedUser.lastName}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            lastName: e.target.value
                          })}
                          required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-nationalId">National ID</Label>
                      <Input
                          id="edit-nationalId"
                          name="nationalId"
                          type="number"
                          value={selectedUser.nationalId}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            nationalId: e.target.value
                          })}
                          required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-username">Username</Label>
                      <Input
                          id="edit-username"
                          name="username"
                          value={selectedUser.username}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            username: e.target.value
                          })}
                          required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-email">Email</Label>
                      <Input
                          id="edit-email"
                          name="email"
                          type="email"
                          value={selectedUser.email}
                          onChange={(e) => setSelectedUser({
                            ...selectedUser,
                            email: e.target.value
                          })}
                          required
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-role">Role</Label>
                      <Select
                          value={selectedUser.role}
                          onValueChange={(value) => setSelectedUser({
                            ...selectedUser,
                            role: value
                          })}
                      >
                        <SelectTrigger className="w-full border border-input">
                          <SelectValue placeholder="Select a role" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectLabel>Available Roles</SelectLabel>
                            <SelectItem value="admin">Admin</SelectItem>
                            <SelectItem value="user">User</SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button
                        variant="outline"
                        type="button"
                        onClick={() => setIsEditUserDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                        type="submit"
                        disabled={isLoading}
                    >
                      {isLoading ? "Updating..." : "Update User"}
                    </Button>
                  </DialogFooter>
                </form>
            )}
          </DialogContent>
        </Dialog>

        <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
          <DialogContent className="sm:max-w-[400px] font-montserrat">
            <DialogHeader>
              <DialogTitle>Delete User</DialogTitle>
              <DialogDescription>
                Are you sure you want to delete this user? This action cannot be undone.
              </DialogDescription>
            </DialogHeader>
            {selectedUser && (
                <div>
                  <div className="py-4">
                    <p className="text-sm text-gray-500">
                      You are about to delete the following user:
                    </p>
                    <p className="mt-2 font-medium">
                      {selectedUser.firstName} {selectedUser.lastName}
                    </p>
                    <p className="text-sm text-gray-500">
                      Username: {selectedUser.username}
                    </p>
                  </div>
                  <DialogFooter>
                    <Button
                        variant="outline"
                        onClick={() => setIsDeleteDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                        variant="destructive"
                        className="bg-red-600 hover:bg-red-700 text-white"
                        onClick={async () => {
                          setIsLoading(true)
                          try {
                            const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
                            if (!userInfo.authToken) {
                              toast.error("Authentication required")
                              setIsLoading(false)
                              return
                            }

                            // Delete user via API
                            await axios.delete(
                                `${API_URL}/delete-user/${selectedUser.id}`,
                                {
                                  headers: {
                                    Authorization: `Bearer ${userInfo.authToken}`,
                                  },
                                }
                            )

                            toast.success("User deleted successfully")
                            setIsDeleteDialogOpen(false)
                            // No need to call fetchUsers, useEffect will refetch
                          } catch (error: any) {
                            console.error("Error deleting user:", error)
                            toast.error(error.response?.data?.error || "Failed to delete user")
                          } finally {
                            setIsLoading(false)
                          }
                        }}
                        disabled={isLoading}
                    >
                      {isLoading ? "Deleting..." : "Delete User"}
                    </Button>
                  </DialogFooter>
                </div>
            )}
          </DialogContent>
        </Dialog>
        <Dialog open={isUnlockAccountDialogOpen} onOpenChange={setIsUnlockAccountDialogOpen}>
          <DialogContent className="sm:max-w-[425px] font-montserrat">
            <DialogHeader>
              <DialogTitle>Unlock User Account</DialogTitle>
              <DialogDescription>
                Are you sure you want to unlock this user's account?
              </DialogDescription>
            </DialogHeader>
            {selectedUser && (
              <div>
                <div className="py-4">
                  <p className="text-sm text-muted-foreground">
                    You are about to unlock the account for:
                  </p>
                  <p className="mt-2 font-medium">
                    {selectedUser.firstName} {selectedUser.lastName}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Username: {selectedUser.username}
                  </p>
                </div>
                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsUnlockAccountDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleUnlockUserAccount}
                    disabled={isLoading}
                  >
                    {isLoading ? "Unlocking..." : "Unlock Account"}
                  </Button>
                </DialogFooter>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </>
  )
}
