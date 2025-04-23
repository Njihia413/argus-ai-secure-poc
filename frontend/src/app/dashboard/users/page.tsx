"use client"

import { useState, useEffect } from "react"
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

// Sample data for the users table
const recentUsersData = [
  {
    id: 1,
    name: "Alex Johnson",
    username: "alex_j",
    email: "alex@example.com",
    role: "Developer",
    hasSecurityKey: true,
    lastLogin: "2 minutes ago",
    status: "Online",
  },
  {
    id: 2,
    name: "Sarah Wilson",
    username: "sarah_w",
    email: "sarah@example.com",
    role: "Security Officer",
    hasSecurityKey: true,
    lastLogin: "42 minutes ago",
    status: "Online",
  },
  {
    id: 3,
    name: "Michael Lee",
    username: "mike_l",
    email: "mike@example.com",
    role: "Analyst",
    hasSecurityKey: false,
    lastLogin: "3 hours ago",
    status: "Offline",
  },
]

// User type definition for real API integration
interface User {
  id: number
  username: string
  firstName: string
  lastName: string
  role: string
  hasSecurityKey: boolean
  lastLogin: string | null
}

// New user form interface for real API integration
interface NewUserFormData {
  firstName: string
  lastName: string
  username: string
  password: string
  role: string
}

export default function UsersPage() {
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
      const response = await axios.get(`${process.env.NEXT_PUBLIC_API_URL || ""}/users`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      })

      // Update state with users from API
      if (response.data && response.data.users) {
        setUsers(response.data.users)
      }
    } catch (error) {
      console.error("Error fetching users:", error)
      toast.error("Failed to load users data")
    } finally {
      setIsLoading(false)
    }
  }

  // New user form state and handlers
  const [newUserForm, setNewUserForm] = useState<NewUserFormData>({
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
      await axios.post(`${process.env.NEXT_PUBLIC_API_URL || ""}/register`, newUserForm, {
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
    <div className="grid gap-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold tracking-tight">Users</h2>
        <Button onClick={() => setIsAddUserDialogOpen(true)} className="bg-teal-600 hover:bg-teal-700">
          <UserPlus className="h-4 w-4 mr-2" />
          Add User
        </Button>
      </div>

      <Card className="shadow-sm hover:shadow-md transition-shadow">
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Security Key</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Last Login</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    Loading...
                  </TableCell>
                </TableRow>
              ) : users.length > 0 ? (
                users.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">
                      {user.firstName} {user.lastName}
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
                      <Badge variant="outline" className="bg-slate-100">
                        {user.role}
                      </Badge>
                    </TableCell>
                    <TableCell>{user.lastLogin || "Never"}</TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem>View Details</DropdownMenuItem>
                          <DropdownMenuItem>Edit User</DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600">Delete User</DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={5} className="text-center">
                    No users found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={isAddUserDialogOpen} onOpenChange={setIsAddUserDialogOpen}>
        <DialogContent className="sm:max-w-[500px]">
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
              <Button type="submit" className="bg-teal-600 hover:bg-teal-700" disabled={isLoading}>
                {isLoading ? "Creating..." : "Create User"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}