"use client"

import { ColumnDef } from "@tanstack/react-table"
import { MoreHorizontal, Trash2, Edit, Eye } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"; // Moved imports up
import React from "react";
import { useRouter } from "next/navigation";
// import { DataTableColumnHeader } from "./data-table-column-header" // Component does not exist

// Updated data type to match backend and page component
export interface SecurityKey {
  id: string | number;
  device_type: string | null;
  form_factor: string | null;
  serialNumber: string | null;
  status: "active" | "inactive"; // Simplified status
  registeredOn: string; // ISO date string
  lastUsed: string; // ISO date string or "Never"
  username: string; // Added username
}

// This interface will be used for the edit form state
interface SecurityKeyDetailsForm {
  device_type: string;
  form_factor: string;
  serialNumber: string;
  pin: string; // Keep as string, backend handles optional empty string
}

// Copied from src/app/dashboard/users/[id]/page.tsx
const securityKeyModels = {
  'YubiKey': [
    'YubiKey 5 NFC',
    'YubiKey 5C',
    'YubiKey 5 Nano',
    'YubiKey Bio',
    'YubiKey 5Ci',
    'YubiKey FIPS'
  ],
  'Google Titan': [
    'Titan Security Key USB-C',
    'Titan Security Key USB-A',
    'Titan Security Key NFC',
    'Titan Security Key Bluetooth'
  ],
  'Feitian': [
    'ePass FIDO2',
    'MultiPass FIDO',
    'BioPass FIDO2',
    'AllinPass FIDO2',
    'K40 FIDO2'
  ],
  'Thetis': [
    'Thetis FIDO2',
    'Thetis Bio',
    'Thetis PRO',
    'Thetis Forte'
  ],
  'SoloKeys': [
    'Solo V2',
    'SoloKey',
    'Solo Tap',
    'Solo Hacker'
  ]
};

const selectionColumn: ColumnDef<SecurityKey> = {
  id: "select",
  header: ({ table }) => (
    <Checkbox
      checked={table.getIsAllPageRowsSelected()}
      onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
      aria-label="Select all"
      className="translate-y-[2px]"
    />
  ),
  cell: ({ row }) => (
    <Checkbox
      checked={row.getIsSelected()}
      onCheckedChange={(value) => row.toggleSelected(!!value)}
      aria-label="Select row"
      className="translate-y-[2px]"
    />
  ),
  enableSorting: false,
  enableHiding: false,
};

export const securityKeysColumns: ColumnDef<SecurityKey>[] = [
  selectionColumn,
  {
    accessorKey: "username",
    header: "User",
    cell: ({ row }) => <div className="font-medium">{row.getValue("username")}</div>,
  },
  {
    accessorKey: "device_type",
    header: "Model",
    cell: ({ row }) => <div>{row.getValue("device_type") || "N/A"}</div>,
  },
  {
    accessorKey: "form_factor",
    header: "Type",
    cell: ({ row }) => <div>{row.getValue("form_factor") || "N/A"}</div>,
  },
  {
    accessorKey: "serialNumber",
    header: "Serial Number",
    cell: ({ row }) => <div>{row.getValue("serialNumber") || "N/A"}</div>,
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const status = row.getValue("status") as SecurityKey["status"];
      let badgeClassName = "border-transparent bg-gray-500 text-gray-50"; // Default for unknown
      if (status === "active") {
        // Consistent with user details page: text-green-700 dark:text-green-400 border-green-300 dark:border-green-700
        badgeClassName = "text-green-700 dark:text-green-400 border-green-300 dark:border-green-700 bg-transparent";
      } else if (status === "inactive") {
        // Consistent with user details page (Security Key Status: Inactive uses red)
        badgeClassName = "text-red-700 dark:text-red-400 border-red-300 dark:border-red-700 bg-transparent";
      }
      return <Badge variant="outline" className={`capitalize ${badgeClassName}`}>{status}</Badge>;
    },
    filterFn: (row, id, value) => {
      return value.includes(row.getValue(id));
    },
  },
  {
    accessorKey: "registeredOn",
    header: "Registered On",
    cell: ({ row }) => {
      const timestamp = row.getValue("registeredOn") as string;
      if (!timestamp) return <span className="text-sm text-muted-foreground">Not available</span>;

      return (
        <div className="text-sm">
          <div className="text-foreground">
            {new Date(timestamp).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            })}
          </div>
          <div className="text-muted-foreground">
            {new Date(timestamp).toLocaleTimeString('en-US', {
              hour: 'numeric',
              minute: '2-digit',
              hour12: true
            })}
          </div>
        </div>
      );
    },
  },
  {
    accessorKey: "lastUsed",
    header: "Last Used",
    cell: ({ row }) => {
      const timestamp = row.getValue("lastUsed") as string;
      if (!timestamp || timestamp === "Never") return <span className="text-sm text-muted-foreground">Never</span>;

      return (
        <div className="text-sm">
          <div className="text-foreground">
            {new Date(timestamp).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              year: 'numeric'
            })}
          </div>
          <div className="text-muted-foreground">
            {new Date(timestamp).toLocaleTimeString('en-US', {
              hour: 'numeric',
              minute: '2-digit',
              hour12: true
            })}
          </div>
        </div>
      );
    },
  },
  {
    id: "actions",
    header: "Action", // Added header label
    cell: ({ row, table }) => {
      const securityKey = row.original
      const router = useRouter();
      const [showDeleteDialog, setShowDeleteDialog] = React.useState(false);
      const [isDeleting, setIsDeleting] = React.useState(false);
      const [showEditModal, setShowEditModal] = React.useState(false);
      const [isUpdatingDetails, setIsUpdatingDetails] = React.useState(false);
      const [editingKeyDetails, setEditingKeyDetails] = React.useState<SecurityKeyDetailsForm>({ // Corrected type
        device_type: securityKey.device_type || "",
        form_factor: securityKey.form_factor || "",
        serialNumber: securityKey.serialNumber || "",
        pin: "",
      });

      // Effect to reset form when modal opens for a new/different key
      React.useEffect(() => {
        if (securityKey && showEditModal) {
          setEditingKeyDetails({
            device_type: securityKey.device_type || "",
            form_factor: securityKey.form_factor || "",
            serialNumber: securityKey.serialNumber || "",
            pin: "",
          });
        }
      }, [securityKey, showEditModal]);


      const handleViewDetails = () => {
        router.push(`/dashboard/security-keys/${securityKey.id}`);
      };

      const handleEditModalOpen = () => {
        setShowEditModal(true);
      };

      const handleEditDetailsSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsUpdatingDetails(true);
        try {
          const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
          if (!userInfo.authToken) {
            toast.error("Authentication required.");
            setIsUpdatingDetails(false);
            return;
          }
          const payload: Partial<SecurityKeyDetailsForm> = { // Corrected type
            device_type: editingKeyDetails.device_type,
            form_factor: editingKeyDetails.form_factor,
            serialNumber: editingKeyDetails.serialNumber,
          };
          if (editingKeyDetails.pin && editingKeyDetails.pin.trim() !== "") {
            payload.pin = editingKeyDetails.pin;
          }

          interface UpdateResponse { // Added interface for response
            message?: string;
            key?: Partial<SecurityKey>;
          }

          const response = await axios.put<UpdateResponse>(`${API_URL}/security-keys/${securityKey.id}`, payload, { // Typed response
            headers: { Authorization: `Bearer ${userInfo.authToken}` },
          });
          toast.success(response.data.message || "Security key details updated.");
          setShowEditModal(false);
          if (table.options.meta && typeof (table.options.meta as any).refreshData === 'function') {
            (table.options.meta as any).refreshData();
          }
        } catch (error: any) {
          toast.error(error.response?.data?.error || "Failed to update security key details.");
        } finally {
          setIsUpdatingDetails(false);
        }
      };

interface DeleteResponse {
  message?: string;
}

      const confirmDelete = async () => {
        setIsDeleting(true);
        try {
          const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
          if (!userInfo.authToken) {
            toast.error("Authentication required to delete.");
            setIsDeleting(false);
            setShowDeleteDialog(false);
            return;
          }
          const response = await axios.delete<DeleteResponse>(`${API_URL}/security-keys/${securityKey.id}`, {
            headers: { Authorization: `Bearer ${userInfo.authToken}` },
          });
          toast.success(response.data.message || "Security key deleted successfully.");
          if (table.options.meta && typeof (table.options.meta as any).refreshData === 'function') {
            (table.options.meta as any).refreshData();
          }
        } catch (error: any) {
          toast.error(error.response?.data?.error || "Failed to delete security key.");
        } finally {
          setIsDeleting(false);
          setShowDeleteDialog(false);
        }
      };


      return (
        <>
          {/* Edit Details Modal */}
          <Dialog open={showEditModal} onOpenChange={setShowEditModal}>
            <DialogContent className="sm:max-w-md font-montserrat">
              <DialogHeader>
                <DialogTitle>Edit Security Key</DialogTitle>
                <DialogDescription>
                  Update the details of the security key.
                </DialogDescription>
              </DialogHeader>
              <form onSubmit={handleEditDetailsSubmit}>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor={`edit-model-${securityKey.id}`}>Security Key Model</Label>
                    <Select
                      value={editingKeyDetails.device_type}
                      onValueChange={(value) => {
                        setEditingKeyDetails({
                          ...editingKeyDetails,
                          device_type: value,
                          form_factor: '' // Reset type when model changes
                        });
                      }}
                    >
                      <SelectTrigger className="w-full border border-input">
                        <SelectValue placeholder="Select Model" />
                      </SelectTrigger>
                      <SelectContent className="w-full min-w-[300px]">
                        <SelectGroup>
                          {Object.keys(securityKeyModels).map((model) => (
                            <SelectItem key={model} value={model}>
                              {model}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor={`edit-type-${securityKey.id}`}>Key Type</Label>
                    <Select
                      value={editingKeyDetails.form_factor}
                      onValueChange={(value) => setEditingKeyDetails({ ...editingKeyDetails, form_factor: value })}
                      disabled={!editingKeyDetails.device_type}
                    >
                      <SelectTrigger className="w-full border border-input">
                        <SelectValue placeholder="Select Type" />
                      </SelectTrigger>
                      <SelectContent className="w-full min-w-[300px]">
                        <SelectGroup>
                          {editingKeyDetails.device_type && securityKeyModels[editingKeyDetails.device_type as keyof typeof securityKeyModels]?.map((form_factor) => (
                            <SelectItem key={form_factor} value={form_factor}>
                              {form_factor}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor={`edit-serialNumber-${securityKey.id}`}>Serial Number</Label>
                    <Input
                        id={`edit-serialNumber-${securityKey.id}`}
                        placeholder="Enter serial number"
                        value={editingKeyDetails.serialNumber}
                        onChange={(e) => setEditingKeyDetails({ ...editingKeyDetails, serialNumber: e.target.value })}
                        required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor={`edit-pin-${securityKey.id}`}>
                      Security Key PIN
                      <span className="text-gray-400 ml-2 text-sm">(Leave blank to keep current PIN)</span>
                    </Label>
                    <Input
                        id={`edit-pin-${securityKey.id}`}
                        type="password"
                        placeholder="Enter new PIN (optional)"
                        value={editingKeyDetails.pin}
                        onChange={(e) => setEditingKeyDetails({ ...editingKeyDetails, pin: e.target.value })}
                    />
                  </div>
                </div>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button type="button" variant="outline" onClick={() => setShowEditModal(false)}>Cancel</Button>
                  </DialogClose>
                  <Button type="submit" disabled={isUpdatingDetails}>
                    {isUpdatingDetails ? (
                      <>
                        <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                        Updating...
                      </>
                    ) : "Update Details"}
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
          
          {/* Delete Confirmation Dialog */}
          <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
            <AlertDialogContent className="font-montserrat">
              <AlertDialogHeader>
                <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                <AlertDialogDescription asChild>
                  <div className="space-y-4">
                    <p>
                      This action cannot be undone. This will permanently delete the security key
                      and remove its data from our servers.
                    </p>
                    <div className="bg-muted p-3 mt-2 rounded border border-yellow-500">
                      <div className="text-sm space-y-1">
                        <div><strong>Model:</strong> {securityKey.device_type || 'N/A'}</div>
                        <div><strong>Serial:</strong> {securityKey.serialNumber || 'N/A'}</div>
                        <div><strong>User:</strong> {securityKey.username}</div>
                      </div>
                    </div>
                  </div>
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel onClick={() => setShowDeleteDialog(false)}>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={confirmDelete}
                  disabled={isDeleting}
                  className="bg-red-600 hover:bg-red-700 text-white"
                >
                  {isDeleting ? (
                    <>
                      <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                      Deleting...
                    </>
                  ) : (
                    "Delete Key"
                  )}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0">
              <span className="sr-only">Open menu</span>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="font-montserrat">
            <DropdownMenuItem onClick={handleEditModalOpen}>
              <Edit className="mr-2 h-4 w-4" />
              Edit Details
            </DropdownMenuItem>
            <DropdownMenuItem onClick={handleViewDetails}>
              <Eye className="mr-2 h-4 w-4" />
              View Details
            </DropdownMenuItem>
            {/* <DropdownMenuSeparator /> Removed separator */}
            <DropdownMenuItem
              onClick={() => setShowDeleteDialog(true)}
              className="text-red-600 hover:!text-red-600 focus:text-red-600 focus:bg-red-50 dark:focus:bg-red-700/10"
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
       </>
      )
    },
  },
]
// Need to import API_URL and axios for delete, and toast
import { API_URL } from "@/app/utils/constants";
import axios from "axios";
import { toast } from "sonner";