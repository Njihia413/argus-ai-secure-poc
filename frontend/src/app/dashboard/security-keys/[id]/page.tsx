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
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { API_URL } from "@/app/utils/constants"
import { fetchWorkstationFingerprint } from "@/app/utils/machine-fingerprint"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
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

interface MachineBinding {
  id: number
  machine_id: string
  machine_name: string | null
  hostname: string | null
  os_info: string | null
  mac_address: string | null
  created_at: string | null
  created_by: string | null
}

// Interface for the detailed security key object from backend
interface SecurityKeyDetail {
  id: number;
  device_type: string | null;
  form_factor: string | null;
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

  // Machine binding state
  const [boundMachines, setBoundMachines] = useState<MachineBinding[]>([])
  const [requireBinding, setRequireBinding] = useState(false)
  const [showBindDialog, setShowBindDialog] = useState(false)
  const [bindingFingerprint, setBindingFingerprint] = useState<{ machine_id: string; components: Record<string, string> } | null>(null)
  const [bindingLabel, setBindingLabel] = useState('')
  const [isFetchingFingerprint, setIsFetchingFingerprint] = useState(false)
  const [isBindingMachine, setIsBindingMachine] = useState(false)
  const [bindingToUnbind, setBindingToUnbind] = useState<MachineBinding | null>(null)
  const [isUpdatingPolicy, setIsUpdatingPolicy] = useState(false)
  const [maxMachines, setMaxMachines] = useState<number>(1)
  const [boundCount, setBoundCount] = useState<number>(0)
  const [maxMachinesInput, setMaxMachinesInput] = useState<string>('1')
  const [isUpdatingMaxMachines, setIsUpdatingMaxMachines] = useState(false)
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
      router.push("/")
      return
    }
    if (userInfo.role !== "admin") {
      toast.error("Admin access required")
      router.push("/dashboard")
      return
    }
    if (keyId) {
      fetchKeyDetails(userInfo.authToken, keyId as string)
      fetchMachineBindings(userInfo.authToken, keyId as string)
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

  const fetchMachineBindings = async (authToken: string, id: string) => {
    try {
      const response = await axios.get<{
        machines: MachineBinding[]
        require_machine_binding: boolean
        max_machines: number
        bound_count: number
      }>(
        `${API_URL}/security-keys/${id}/machines`,
        { headers: { Authorization: `Bearer ${authToken}` } }
      )
      setBoundMachines(response.data.machines)
      setRequireBinding(response.data.require_machine_binding)
      const max = response.data.max_machines ?? 1
      const count = response.data.bound_count ?? response.data.machines.length
      setMaxMachines(max)
      setBoundCount(count)
      setMaxMachinesInput(String(max))
    } catch {
      // Non-critical — page still works without binding data
    }
  }

  const handleToggleBindingPolicy = async (checked: boolean) => {
    setIsUpdatingPolicy(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.put(
        `${API_URL}/security-keys/${keyId}/binding-policy`,
        { require_machine_binding: checked },
        { headers: { Authorization: `Bearer ${userInfo.authToken}` } }
      )
      setRequireBinding(checked)
      toast.success(`Machine binding ${checked ? 'enabled' : 'disabled'}`)
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to update binding policy")
    } finally {
      setIsUpdatingPolicy(false)
    }
  }

  const handleOpenBindDialog = async () => {
    setBindingLabel('')
    setBindingFingerprint(null)
    setShowBindDialog(true)
    setIsFetchingFingerprint(true)
    try {
      const fingerprint = await fetchWorkstationFingerprint()
      setBindingFingerprint(fingerprint)
    } catch (error: any) {
      toast.error(error.message || "Failed to capture machine fingerprint")
      setShowBindDialog(false)
    } finally {
      setIsFetchingFingerprint(false)
    }
  }

  const handleBindMachine = async () => {
    if (!bindingFingerprint) return
    setIsBindingMachine(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.post(
        `${API_URL}/security-keys/${keyId}/bind-machine`,
        {
          machine_id: bindingFingerprint.machine_id,
          components: bindingFingerprint.components,
          machine_name: bindingLabel || bindingFingerprint.components.hostname || 'Machine',
        },
        { headers: { Authorization: `Bearer ${userInfo.authToken}` } }
      )
      toast.success("Machine bound successfully")
      setShowBindDialog(false)
      fetchMachineBindings(userInfo.authToken, keyId as string)
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to bind machine")
    } finally {
      setIsBindingMachine(false)
    }
  }

  const handleUpdateMaxMachines = async () => {
    const newMax = parseInt(maxMachinesInput, 10)
    if (isNaN(newMax) || newMax < 1) {
      toast.error("Max machines must be at least 1")
      return
    }
    if (newMax === maxMachines) return
    setIsUpdatingMaxMachines(true)
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.put(
        `${API_URL}/security-keys/${keyId}/binding-policy`,
        { max_machines: newMax },
        { headers: { Authorization: `Bearer ${userInfo.authToken}` } }
      )
      setMaxMachines(newMax)
      toast.success(`Machine limit updated to ${newMax}`)
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to update machine limit")
      setMaxMachinesInput(String(maxMachines)) // revert on failure
    } finally {
      setIsUpdatingMaxMachines(false)
    }
  }

  const handleUnbindMachine = async () => {
    if (!bindingToUnbind) return
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      await axios.delete(
        `${API_URL}/security-keys/${keyId}/machines/${bindingToUnbind.id}`,
        { headers: { Authorization: `Bearer ${userInfo.authToken}` } }
      )
      toast.success("Machine unbound successfully")
      setBindingToUnbind(null)
      fetchMachineBindings(userInfo.authToken, keyId as string)
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to unbind machine")
      setBindingToUnbind(null)
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
          <span className="text-foreground">{securityKey.device_type || `Key ID: ${securityKey.id}`}</span>
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
            <p className="text-sm font-medium text-muted-foreground">Device Type</p>
            <p className="text-lg">{securityKey.device_type || "N/A"}</p>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Form Factor</p>
            <p className="text-lg">{securityKey.form_factor || "N/A"}</p>
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
            <div className="text-sm">
              <div className="text-foreground">
                {securityKey.registeredOn ? new Date(securityKey.registeredOn).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                }) : "N/A"}
              </div>
              <div className="text-muted-foreground">
                {securityKey.registeredOn ? new Date(securityKey.registeredOn).toLocaleTimeString('en-US', {
                  hour: 'numeric',
                  minute: '2-digit',
                  hour12: true
                }) : ""}
              </div>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Last Used</p>
            <div className="text-sm">
              <div className="text-foreground">
                {securityKey.lastUsed === "Never" ? "Never" : (securityKey.lastUsed ? new Date(securityKey.lastUsed).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                }) : "N/A")}
              </div>
              <div className="text-muted-foreground">
                {securityKey.lastUsed && securityKey.lastUsed !== "Never" ? new Date(securityKey.lastUsed).toLocaleTimeString('en-US', {
                  hour: 'numeric',
                  minute: '2-digit',
                  hour12: true
                }) : ""}
              </div>
            </div>
          </div>
          {securityKey.deactivatedAt && (
            <div className="space-y-1">
              <p className="text-sm font-medium text-muted-foreground">Deactivated On</p>
              <div className="text-sm">
                <div className="text-foreground">
                  {new Date(securityKey.deactivatedAt).toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric'
                  })}
                </div>
                <div className="text-muted-foreground">
                  {new Date(securityKey.deactivatedAt).toLocaleTimeString('en-US', {
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true
                  })}
                </div>
              </div>
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
                      className="max-w-sm bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent"
                    />
                    <Select
                      value={actionFilterValue}
                      onValueChange={(value) => {
                        setActionFilterValue(value);
                      }}
                    >
                      <SelectTrigger className="w-auto bg-white dark:bg-zinc-900 border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
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

      {/* Machine Binding Card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Machine Binding</CardTitle>
            <CardDescription>Restrict this key to specific workstations</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="require-binding" className="text-sm text-muted-foreground">
              {requireBinding ? 'Enforced' : 'Not enforced'}
            </Label>
            <Switch
              id="require-binding"
              checked={requireBinding}
              onCheckedChange={handleToggleBindingPolicy}
              disabled={isUpdatingPolicy}
            />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {!requireBinding && (
            <div className="bg-yellow-50 dark:bg-transparent border border-yellow-300 dark:border-yellow-700 rounded p-3 text-sm text-yellow-800 dark:text-yellow-400">
              Machine binding is not enforced. Enable the toggle to require this key to be used only from bound machines.
            </div>
          )}

          {/* Machine limit control */}
          <div className="flex items-center gap-3">
            <Label className="text-sm text-muted-foreground whitespace-nowrap">
              Machine limit:
            </Label>
            <Input
              type="number"
              min={1}
              value={maxMachinesInput}
              onChange={(e) => setMaxMachinesInput(e.target.value)}
              onBlur={handleUpdateMaxMachines}
              onKeyDown={(e) => { if (e.key === 'Enter') handleUpdateMaxMachines() }}
              className="w-20 h-8 text-sm"
              disabled={isUpdatingMaxMachines}
            />
            <span className="text-sm text-muted-foreground">
              ({boundCount} of {maxMachines} bound)
            </span>
          </div>

          {boundMachines.length === 0 ? (
            <p className="text-sm text-muted-foreground">No machines bound to this key.</p>
          ) : (
            <div className="rounded-md border border-[var(--card-border-themed)]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="px-4">Label</TableHead>
                    <TableHead className="px-4">Hostname</TableHead>
                    <TableHead className="px-4">OS</TableHead>
                    <TableHead className="px-4">MAC Address</TableHead>
                    <TableHead className="px-4">Bound On</TableHead>
                    <TableHead className="px-4"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {boundMachines.map((m) => (
                    <TableRow key={m.id}>
                      <TableCell className="px-4">{m.machine_name || '—'}</TableCell>
                      <TableCell className="px-4">{m.hostname || '—'}</TableCell>
                      <TableCell className="px-4">{m.os_info || '—'}</TableCell>
                      <TableCell className="px-4 font-mono text-xs">{m.mac_address || '—'}</TableCell>
                      <TableCell className="px-4 text-muted-foreground">
                        {m.created_at ? new Date(m.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                      </TableCell>
                      <TableCell className="px-4 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={() => setBindingToUnbind(m)}
                        >
                          Unbind
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenBindDialog}
            disabled={boundCount >= maxMachines}
            title={boundCount >= maxMachines ? `Limit of ${maxMachines} machine(s) reached. Increase the limit or unbind a machine.` : undefined}
          >
            Add Machine
          </Button>
          {boundCount >= maxMachines && (
            <p className="text-xs text-muted-foreground">
              Limit reached. Increase the machine limit or unbind an existing machine to add another.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Bind Machine Dialog */}
      <Dialog open={showBindDialog} onOpenChange={setShowBindDialog}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>Bind Current Machine</DialogTitle>
            <DialogDescription>
              The machine running this server will be added as an authorised workstation for this key.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            {isFetchingFingerprint ? (
              <p className="text-sm text-muted-foreground flex items-center gap-2">
                <span className="animate-spin rounded-full h-4 w-4 border-b-2 border-current inline-block"></span>
                Capturing machine fingerprint...
              </p>
            ) : bindingFingerprint ? (
              <div className="bg-muted/50 border border-[var(--card-border-themed)] rounded-md p-3 text-sm space-y-1">
                <p><span className="font-medium">Hostname:</span> {bindingFingerprint.components.hostname}</p>
                <p><span className="font-medium">OS:</span> {bindingFingerprint.components.os}</p>
                <p><span className="font-medium">MAC Address:</span> {bindingFingerprint.components.mac_address}</p>
              </div>
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="binding-label">Machine Label (optional)</Label>
              <Input
                id="binding-label"
                placeholder="e.g. Server Room Workstation"
                value={bindingLabel}
                onChange={(e) => setBindingLabel(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowBindDialog(false)}>Cancel</Button>
            <Button
              onClick={handleBindMachine}
              disabled={isBindingMachine || !bindingFingerprint}
            >
              {isBindingMachine ? (
                <>
                  <span className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2 inline-block"></span>
                  Binding...
                </>
              ) : 'Bind Machine'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Unbind Confirmation */}
      <AlertDialog open={!!bindingToUnbind} onOpenChange={(open) => !open && setBindingToUnbind(null)}>
        <AlertDialogContent className="font-montserrat">
          <AlertDialogHeader>
            <AlertDialogTitle>Unbind Machine</AlertDialogTitle>
            <AlertDialogDescription>
              Remove <strong>{bindingToUnbind?.machine_name || bindingToUnbind?.hostname || 'this machine'}</strong> from the authorised workstations for this security key?
              {requireBinding && " The key will be rejected when inserted from this machine."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700" onClick={handleUnbindMachine}>
              Unbind
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
// AuditDataTable import moved to the top