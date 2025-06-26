"use client"

import React, { useState, useEffect, useMemo } from "react"
import Link from "next/link"
import { useParams, useRouter } from "next/navigation"
import { ArrowLeft, ChevronDown, ChevronRight } from 'lucide-react'
import axios from "axios"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { API_URL } from "@/app/utils/constants"
import { DataTable } from "@/components/data-table/data-table"
import { SecurityKeyAuditLog, columns as securityKeyAuditColumns } from "@/components/data-table/security-key-audit-columns"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

// Security key specific action options for filtering - matching backend values and display labels
const actionOptions = [
  { value: "all", label: "All Actions" },
  { value: "initial-register", label: "Initial Registration" },
  { value: "re-register", label: "Re-Registration" },
  { value: "deactivate", label: "Deactivation" },
  { value: "reset", label: "Reset" },
  { value: "reassign", label: "Reassignment" }
]

// Interface for the detailed security key object from backend
interface SecurityKeyDetail {
  id: number;
  model: string | null;
  type: string | null;
  serialNumber: string | null;
  status: "active" | "inactive";
  isActive: boolean;
  registeredOn: string | null;
  lastUsed: string | null;
  deactivatedAt: string | null;
  deactivationReason: string | null;
  credentialId: string | null;
  publicKey: string | null;
  signCount: number | null;
  user: {
    id: number;
    username: string;
    firstName: string;
    lastName: string;
  };
  auditLogs: SecurityKeyAuditLog[];
}

export default function SecurityKeyDetailsPage() {
  const router = useRouter()
  const params = useParams()
  const keyId = params.id

  const [securityKey, setSecurityKey] = useState<SecurityKeyDetail | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [actionFilterValue, setActionFilterValue] = useState<string>("all")
  const [searchFilter, setSearchFilter] = useState("")
  const [pagination, setPagination] = useState({
    pageIndex: 0,
    pageSize: 10,
  })
  const [pageCount, setPageCount] = useState(0)
  // Add state for delete confirmation later
  // const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  // const [isDeleting, setIsDeleting] = useState(false);

  const filteredLogs = useMemo(() => {
    if (!securityKey?.auditLogs) return []
    return securityKey.auditLogs
      .filter(log => {
        const searchTerm = searchFilter.toLowerCase()
        return (
          log.action.toLowerCase().includes(searchTerm) ||
          log.performedBy.username.toLowerCase().includes(searchTerm) ||
          log.timestamp.toLowerCase().includes(searchTerm) ||
          (log.details && log.details.toLowerCase().includes(searchTerm))
        )
      })
      .filter(log => {
        if (actionFilterValue === "all") return true
        return log.action === actionFilterValue
      })
  }, [securityKey, searchFilter, actionFilterValue])

  const paginatedAuditLogs = useMemo(() => {
    const start = pagination.pageIndex * pagination.pageSize
    const end = start + pagination.pageSize
    return filteredLogs.slice(start, end)
  }, [filteredLogs, pagination])

  useEffect(() => {
    setPageCount(Math.ceil(filteredLogs.length / pagination.pageSize))
  }, [filteredLogs, pagination.pageSize])

  useEffect(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
    if (!userInfo || !userInfo.authToken) {
      toast.error("You need to log in")
      router.push("/home")
      return
    }
    if (userInfo.role !== "admin") {
      toast.error("Admin access required")
      router.push("/dashboard")
      return
    }
    if (keyId) {
      fetchKeyDetails(userInfo.authToken, keyId as string)
    }
  }, [router, keyId])

  const fetchKeyDetails = async (authToken: string, id: string) => {
    setIsLoading(true)
    try {
      const response = await axios.get<{ securityKey: SecurityKeyDetail }>(
        `${API_URL}/security-keys/${id}`,
        {
          headers: { Authorization: `Bearer ${authToken}` },
        }
      )
      if (response.data && response.data.securityKey) {
        setSecurityKey(response.data.securityKey)
      } else {
        toast.error("Security key not found")
        router.push("/dashboard/security-keys")
      }
    } catch (error: any) {
      console.error("Error fetching security key details:", error)
      toast.error(error.response?.data?.error || "Failed to load security key details")
      router.push("/dashboard/security-keys")
    } finally {
      setIsLoading(false)
    }
  }
  
  // Placeholder for delete action
  const handleDeleteKey = async () => {
    if (!securityKey) return;
    // setIsDeleting(true);
    // try {
    //   const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    //   await axios.delete(`${API_URL}/security-keys/${securityKey.id}`, {
    //     headers: { Authorization: `Bearer ${userInfo.authToken}` },
    //   });
    //   toast.success("Security key deleted successfully");
    //   router.push("/dashboard/security-keys");
    // } catch (error: any) {
    //   toast.error(error.response?.data?.error || "Failed to delete security key");
    // } finally {
    //   setIsDeleting(false);
    //   setShowDeleteConfirm(false);
    // }
    console.log("Delete key action for ID:", securityKey.id)
    toast.info("Delete functionality to be implemented.")
  };


  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-screen space-y-2 text-muted-foreground">
        <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
        <span>Loading security key details...</span>
      </div>
    )
  }

  if (!securityKey) {
    return (
      <div className="flex flex-col items-center justify-center h-screen">
        <p className="text-xl text-muted-foreground">Security key not found.</p>
        <Button onClick={() => router.push("/dashboard/security-keys")} className="mt-4">
          Go Back
        </Button>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6 p-4 md:p-6 font-montserrat">
      <div className="flex justify-between items-center">
        <div className="flex items-center text-sm text-muted-foreground">
          <Link href="/dashboard" className="hover:text-foreground">Dashboard</Link>
          <ChevronRight className="h-4 w-4 mx-1" />
          <Link href="/dashboard/security-keys" className="hover:text-foreground">Security Keys</Link>
          <ChevronRight className="h-4 w-4 mx-1" />
          <span className="text-foreground">{securityKey.model || `Key ID: ${securityKey.id}`}</span>
        </div>
        <Button onClick={() => router.push("/dashboard/security-keys")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Security Keys
        </Button>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Security Key Details</CardTitle>
            <CardDescription>
              Viewing details for key: {securityKey.serialNumber || securityKey.id}
            </CardDescription>
          </div>
          {/* Edit and Delete buttons removed from here */}
        </CardHeader>
        <CardContent className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Key ID</p>
            <p className="text-lg">{securityKey.id}</p>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Model</p>
            <p className="text-lg">{securityKey.model || "N/A"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Type</p>
            <p className="text-lg">{securityKey.type || "N/A"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Serial Number</p>
            <p className="text-lg">{securityKey.serialNumber || "N/A"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Status</p>
            <Badge variant="outline" className={`capitalize ${securityKey.isActive ? "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700 bg-transparent" : "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700 bg-transparent"}`}>
              {securityKey.status}
            </Badge>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Registered On</p>
            <p className="text-lg">{securityKey.registeredOn ? new Date(securityKey.registeredOn).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : "N/A"}</p>
            {securityKey.registeredOn && <p className="text-xs text-foreground">{new Date(securityKey.registeredOn).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</p>}
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Last Used</p>
            <p className="text-lg">{securityKey.lastUsed === "Never" ? "Never" : (securityKey.lastUsed ? new Date(securityKey.lastUsed).toLocaleString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : "N/A")}</p>
            {securityKey.lastUsed && securityKey.lastUsed !== "Never" && <p className="text-xs text-foreground">{new Date(securityKey.lastUsed).toLocaleTimeString('en-US', { second: '2-digit', timeZoneName: 'shortOffset' })}</p>}
          </div>
          {securityKey.deactivatedAt && (
            <div className="space-y-1">
              <p className="text-sm font-medium text-muted-foreground">Deactivated On</p>
              <p className="text-lg">{new Date(securityKey.deactivatedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
              <p className="text-xs text-foreground">{new Date(securityKey.deactivatedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</p>
            </div>
          )}
          {securityKey.deactivationReason && (
            <div className="space-y-1 md:col-span-2 lg:col-span-1">
              <p className="text-sm font-medium text-muted-foreground">Deactivation Reason</p>
              <p className="text-lg">{securityKey.deactivationReason}</p>
            </div>
          )}
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Registered To</p>
            <Link href={`/dashboard/users/${securityKey.user.id}`} className="text-lg text-primary hover:underline">
              {securityKey.user.firstName} {securityKey.user.lastName} ({securityKey.user.username})
            </Link>
          </div>
          {/* Credential ID and Sign Count removed */}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security Key History</CardTitle> {/* Title Changed */}
          <CardDescription>
            History of actions performed on this security key.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {securityKey.auditLogs && securityKey.auditLogs.length > 0 ? (
            <DataTable
              columns={securityKeyAuditColumns}
              data={paginatedAuditLogs}
              pageCount={pageCount}
              state={{
                sorting: [],
                columnFilters: [],
                columnVisibility: {},
                rowSelection: {},
                pagination,
              }}
              onPaginationChange={setPagination}
              enableRowSelection={true}
              toolbar={(table) => (
                <div className="flex items-center justify-between w-full font-montserrat">
                  <div className="flex flex-1 items-center space-x-4">
                    <Input
                      placeholder="Search security key audit logs..."
                      value={searchFilter}
                      onChange={(event) =>
                        setSearchFilter(event.target.value)
                      }
                      className="max-w-sm dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                    />
                    <Select
                      value={actionFilterValue}
                      onValueChange={(value) => {
                        setActionFilterValue(value);
                      }}
                    >
                      <SelectTrigger className="w-auto dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                        <SelectValue placeholder="Filter by action" />
                      </SelectTrigger>
                      <SelectContent>
                        {actionOptions.map(option => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
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
                            {column.id}
                          </DropdownMenuCheckboxItem>
                        ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              )}
            />
          ) : (
            <p className="text-muted-foreground">No audit logs available for this security key.</p>
          )}
        </CardContent>
      </Card>

      {/* Add AlertDialog for delete confirmation later - this would be triggered from the main table now */}
      {/* <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}> ... </AlertDialog> */}
    </div>
  )
}
// AuditDataTable import moved to the top