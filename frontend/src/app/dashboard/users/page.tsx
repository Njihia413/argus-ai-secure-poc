"use client"

import { useState, useEffect } from "react"
import { API_URL } from "@/app/utils/constants"
import { useRouter } from "next/navigation"
import { UserPlus, MoreHorizontal } from "lucide-react"
import axios from "axios"
import { toast } from "sonner"

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
  username: string
  firstName: string
  lastName: string
  role: string
  hasSecurityKey: boolean
  lastLogin: string | null
  loginAttempts: number
  failedAttempts: number
}

// New user form interface for real API integration
interface UserFormData {
  firstName: string
  lastName: string
  username: string
  password: string
  role: string
}

export default function UsersPage() {
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [isEditUserDialogOpen, setIsEditUserDialogOpen] = useState(false)
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)
  const router = useRouter()
  const [isAddUserDialogOpen, setIsAddUserDialogOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [users, setUsers] = useState<User[]>([])

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
      const response = await axios.get(`${API_URL}/users`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })

      // Update state with users from API
      if (response.data && response.data.users) {
        setUsers(response.data.users)
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
    lastName: "",
    username: "",
    password: "",
    role: "user",
  })

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
        lastName: "",
        username: "",
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

  return (
    <div className="grid gap-6 w-full">
      <div className="flex justify-between items-center bg-white p-4">
        <h2 className="text-2xl font-bold tracking-tight">Users</h2>
        <Button onClick={() => setIsAddUserDialogOpen(true)} className="bg-black hover:bg-black/90 text-white">
          <UserPlus className="h-4 w-4 mr-2" />
          Add User
        </Button>
      </div>

      <Card className="shadow-sm hover:shadow-md transition-shadow">
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>First Name</TableHead>
                <TableHead>Last Name</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Security Key</TableHead>
                <TableHead>Last Login</TableHead>
                <TableHead>Successful Logins</TableHead>
                <TableHead>Failed Attempts</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8">
                    <div className="flex flex-col items-center space-y-2 text-slate-500">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-600"></div>
                      <span>Loading users...</span>
                    </div>
                  </TableCell>
                </TableRow>
              ) : users.length > 0 ? (
                [...users]
                  .sort((a, b) => {
                    // Handle null values
                    if (!a.lastLogin) return 1  // null values go to the end
                    if (!b.lastLogin) return -1
                    // Sort by last login time in descending order
                    return new Date(b.lastLogin).getTime() - new Date(a.lastLogin).getTime()
                  })
                  .map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.firstName}</TableCell>
                    <TableCell>{user.lastName}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="bg-slate-100">
                        {user.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {user.hasSecurityKey ? (
                        <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                          Registered
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-amber-50 text-amber-700 border-amber-200">
                          Not Registered
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      {user.lastLogin ? (
                        <div className="text-sm text-muted-foreground">
                          <div>
                            {new Date(user.lastLogin).toLocaleDateString('en-US', {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric'
                            })}
                          </div>
                          <div>
                            {new Date(user.lastLogin).toLocaleTimeString('en-US', {
                              hour: 'numeric',
                              minute: '2-digit',
                              hour12: true
                            })}
                          </div>
                        </div>
                      ) : (
                        <span className="text-sm text-muted-foreground">Not available</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={`${user.loginAttempts > 0 ? "bg-green-50 text-green-700 border-green-200" : "bg-slate-100"}`}
                      >
                        {user.loginAttempts}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={`${user.failedAttempts > 0 ? "bg-red-50 text-red-700 border-red-200" : "bg-slate-100"}`}
                      >
                        {user.failedAttempts}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="font-montserrat">
                          <DropdownMenuItem onClick={() => router.push(`/dashboard/users/${user.id}`)}>
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => {
                            setSelectedUser(user)
                            setIsEditUserDialogOpen(true)
                          }}>
                            Edit User
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-red-600"
                            onClick={() => {
                              setSelectedUser(user)
                              setIsDeleteDialogOpen(true)
                            }}
                          >
                            Delete User
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-slate-500">
                    No users found. Create one by clicking the "Add User" button above.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

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
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  value={newUserForm.password}
                  onChange={handleNewUserInputChange}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="role">Role</Label>
                <Select value={newUserForm.role} onValueChange={handleRoleChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a role" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectLabel>System Roles</SelectLabel>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="security_officer">Security Officer</SelectItem>
                    </SelectGroup>
                    <SelectGroup>
                      <SelectLabel>General Roles</SelectLabel>
                      <SelectItem value="user">User</SelectItem>
                      <SelectItem value="guest">Guest</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => setIsAddUserDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" className="bg-black hover:bg-black/90 text-white" disabled={isLoading}>
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
                    lastName: selectedUser.lastName,
                    username: selectedUser.username,
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
                  <Label htmlFor="edit-role">Role</Label>
                  <Select
                    value={selectedUser.role}
                    onValueChange={(value) => setSelectedUser({
                      ...selectedUser,
                      role: value
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select a role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>System Roles</SelectLabel>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="security_officer">Security Officer</SelectItem>
                      </SelectGroup>
                      <SelectGroup>
                        <SelectLabel>General Roles</SelectLabel>
                        <SelectItem value="user">User</SelectItem>
                        <SelectItem value="guest">Guest</SelectItem>
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
                  className="bg-black hover:bg-black/90 text-white"
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
                        `${API_URL}/users/${selectedUser.id}`,
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
    </div>
  )
}
