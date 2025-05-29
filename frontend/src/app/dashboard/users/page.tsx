"use client"

import { useState, useEffect } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import { UserPlus, Eye, EyeOff, LockOpen } from "lucide-react"
import axios from "axios"
import { toast } from "sonner"
import { DataTable } from "@/components/data-table/data-table"
import { columns } from "@/components/data-table/columns"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
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
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
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
import { Badge } from "@/components/ui/badge"
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
  loginAttempts: number
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
  const [isUnlockAccountDialogOpen, setIsUnlockAccountDialogOpen] = useState(false) // New state for unlock dialog
  const router = useRouter()
  const [isAddUserDialogOpen, setIsAddUserDialogOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [users, setUsers] = useState<User[]>([])
  const [searchTerm, setSearchTerm] = useState("")
  const [roleFilter, setRoleFilter] = useState("all") // 'all', 'admin', 'user'
  const [securityKeyFilter, setSecurityKeyFilter] = useState("all") // 'all', 'none', 'active', 'inactive'
  const [accountStatusFilter, setAccountStatusFilter] = useState("all") // 'all', 'locked', 'unlocked'

  // Initial load
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

    // Load users data
    fetchUsers(userInfo.authToken)
  }, [router])

  const fetchUsers = async (authToken: string) => {
    try {
      setIsLoading(true)
      const response = await axios.get<{ users: User[] }>(`${API_URL}/users`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })

      // Update state with users from API
      if (response.data && response.data.users) {
        // Sort users by lastLogin date in descending order
        const sortedUsers = response.data.users.sort((a: User, b: User) => {
          const dateA = a.lastLogin ? new Date(a.lastLogin).getTime() : 0; // Treat null/undefined as oldest
          const dateB = b.lastLogin ? new Date(b.lastLogin).getTime() : 0;
          return dateB - dateA; // Descending order
        });
        setUsers(sortedUsers)
      } else {
        console.error("Invalid response format:", response.data)
        toast.error("Invalid data format received from server")
      }
    } catch (error: any) {
      console.error("Error fetching users:", error.response?.data || error.message)
      toast.error(error.response?.data?.error || "Failed to load users data")
    } finally {
      setIsLoading(false)
    }
  }

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
      fetchUsers(userInfo.authToken)
    } catch (error: any) {
      console.error("Error creating user:", error)
      toast.error(error.response?.data?.error || "Failed to create user")
    } finally {
      setIsLoading(false)
    }
  }

  const filteredUsers = users.filter(user => {
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      (user.username.toLowerCase()).includes(term) ||
      (user.firstName.toLowerCase()).includes(term) ||
      (user.middlename ? user.middlename.toLowerCase().includes(term) : false) ||
      (user.lastName.toLowerCase()).includes(term) ||
      (user.email.toLowerCase()).includes(term) ||
      (String(user.nationalId).toLowerCase()).includes(term);

    const matchesRole = roleFilter === "all" || user.role === roleFilter;

    let matchesSecurityKey = true;
    if (securityKeyFilter === "none") {
      matchesSecurityKey = !user.hasSecurityKey;
    } else if (securityKeyFilter === "active") {
      matchesSecurityKey = user.hasSecurityKey && user.securityKeyStatus === "active";
    } else if (securityKeyFilter === "inactive") {
      matchesSecurityKey = user.hasSecurityKey && user.securityKeyStatus === "inactive";
    }

    let matchesAccountStatus = true;
    if (accountStatusFilter === "locked") {
      matchesAccountStatus = user.account_locked === true;
    } else if (accountStatusFilter === "unlocked") {
      matchesAccountStatus = user.account_locked === false;
    }

    return matchesSearch && matchesRole && matchesSecurityKey && matchesAccountStatus;
  });

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
      setIsUnlockAccountDialogOpen(false); // Close dialog on success
      fetchUsers(authToken); // Refresh users list
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
            <UserPlus className="h-4 w-4 mr-2" />
            Add User
          </Button>
        </div>

        <div className="px-4 py-4">
          <Card className="shadow-sm hover:shadow-md transition-shadow">
            <CardContent>
              {isLoading ? (
                  <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                    <span>Loading users...</span>
                  </div>
              ) : (
                  <DataTable
                      columns={columns}
                      data={filteredUsers}
                      meta={{
                        setSelectedUser,
                        setIsDeleteDialogOpen,
                        setIsEditUserDialogOpen,
                        setIsUnlockAccountDialogOpen, // Pass setter to DataTable
                      }}
                      toolbar={
                        <div className="flex items-center space-x-4 w-full font-montserrat">
                          <Input
                            placeholder="Search users..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="max-w-sm"
                          />
                          <Select value={roleFilter} onValueChange={setRoleFilter}>
                            <SelectTrigger className="w-[180px] border border-input">
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
                            <SelectTrigger className="w-[220px] border border-input">
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
                            <SelectTrigger className="w-[220px] border border-input">
                              <SelectValue placeholder="Filter by Status" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectGroup>
                                <SelectItem value="all">All Acount Statuses</SelectItem>
                                <SelectItem value="locked">Locked</SelectItem>
                                <SelectItem value="unlocked">Unlocked</SelectItem>
                              </SelectGroup>
                            </SelectContent>
                          </Select>
                        </div>
                      }
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
                    const response = await axios.put(
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
                    fetchUsers(userInfo.authToken)
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
                            fetchUsers(userInfo.authToken)
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
