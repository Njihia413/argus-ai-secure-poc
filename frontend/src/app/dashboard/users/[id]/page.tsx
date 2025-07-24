"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import { useParams, useRouter } from "next/navigation"
import { Key, ChevronRight, ArrowLeft } from 'lucide-react'
import axios from "axios"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
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
import { SecurityDataTable } from "@/components/data-table/security-data-table"
import { securityKeyColumns } from "@/components/data-table/security-key-columns"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { YubiKeyDetectionModal } from "@/components/data-table/yubikey-detection-modal"
import { registerSecurityKey } from "@/app/utils/webauthn"
import { API_URL } from "@/app/utils/constants"

interface User {
  id: number
  nationalId: number
  username: string
  firstName: string
  middlename: string | null
  lastName: string
  email: string
  role: string
  hasSecurityKey: boolean
  securityKeyCount: number
  lastLogin: string | null
  loginAttempts: number
  failedAttempts: number
  account_locked: boolean
  locked_time: string | null
}

interface SecurityKey {
  id: number
  credentialId: string
  isActive: boolean
  createdAt: string
  lastUsed: string | null
  deactivatedAt: string | null
  deactivationReason: string | null
  model?: string
  type?: string
  serialNumber?: string
  public_key?: string
  sign_count?: number
}

interface SecurityKeyDetails {
  model: string
  type: string
  serialNumber: string
  pin: string
}

interface YubiKey {
  serial: number;
  version: string;
  form_factor: string;
  device_type: string;
  is_fips: boolean;
  is_sky: boolean;
}

export default function UserDetailsPage() {
  const router = useRouter()
  const params = useParams()
  const [user, setUser] = useState<User | null>(null)
  const [securityKeys, setSecurityKeys] = useState<SecurityKey[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [showDeactivateDialog, setShowDeactivateDialog] = useState(false)
  const [deactivationReason, setDeactivationReason] = useState('')
  const [isDeactivating, setIsDeactivating] = useState(false)
  const [showRegistrationModal, setShowRegistrationModal] = useState(false)
  const [showKeyDetailsModal, setShowKeyDetailsModal] = useState(false)
  const [isRegistering, setIsRegistering] = useState(false)
  const [isUpdating, setIsUpdating] = useState(false)
  const [selectedKey, setSelectedKey] = useState<SecurityKey | null>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [isResetting, setIsResetting] = useState(false)
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [keyIdToReset, setKeyIdToReset] = useState<number | null>(null);
  const [showReassignDialog, setShowReassignDialog] = useState(false);
  const [usersList, setUsersList] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [isReassigning, setIsReassigning] = useState(false);
  const [keyIdForReassignment, setKeyIdForReassignment] = useState<number | null>(null);
  const [isKeyReassigned, setIsKeyReassigned] = useState<boolean>(false);
  const [keyDetails, setKeyDetails] = useState<SecurityKeyDetails>({
    model: '',
    type: '',
    serialNumber: '',
    pin: ''
  })
  const [isDetectionModalOpen, setIsDetectionModalOpen] = useState(false)

  const securityKeyModels = {
    'YubiKey': ['YubiKey 5 NFC', 'YubiKey 5C', 'YubiKey 5 Nano', 'YubiKey Bio', 'YubiKey 5Ci', 'YubiKey FIPS'],
    'Google Titan': ['Titan Security Key USB-C', 'Titan Security Key USB-A', 'Titan Security Key NFC', 'Titan Security Key Bluetooth'],
    'Feitian': ['ePass FIDO2', 'MultiPass FIDO', 'BioPass FIDO2', 'AllinPass FIDO2', 'K40 FIDO2'],
    'Thetis': ['Thetis FIDO2', 'Thetis Bio', 'Thetis PRO', 'Thetis Forte'],
    'SoloKeys': ['Solo V2', 'SoloKey', 'Solo Tap', 'Solo Hacker']
  }

  useEffect(() => {
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
    fetchUserDetails(userInfo.authToken)
  }, [router, params.id])

  useEffect(() => {
    if (showReassignDialog) {
      fetchAvailableUsers();
    }
  }, [showReassignDialog]);

  const fetchUserDetails = async (authToken: string) => {
    try {
      setIsLoading(true)
      const response = await axios.get<{ user: User }>(`${API_URL}/users/${params.id}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      })
      if (response.data && response.data.user) {
        setUser(response.data.user)
        await fetchSecurityKeys(authToken)
      } else {
        toast.error("User not found")
        router.push("/dashboard/users")
      }
    } catch (error: any) {
      console.error("Error fetching user details:", error)
      toast.error(error.response?.data?.error || "Failed to load user details")
      router.push("/dashboard/users")
    } finally {
      setIsLoading(false)
    }
  }

  const fetchSecurityKeys = async (authToken: string) => {
    try {
      const response = await axios.get<{ securityKeys: SecurityKey[] }>(`${API_URL}/users/${params.id}/security-keys`, {
        headers: { Authorization: `Bearer ${authToken}` },
      })
      if (response.data && response.data.securityKeys) {
        setSecurityKeys(response.data.securityKeys)
      }
    } catch (error: any) {
      console.error("Error fetching security keys:", error)
      toast.error(error.response?.data?.error || "Failed to load security keys")
    }
  }

  const handleSelectYubiKey = async (key: YubiKey) => {
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
      const response = await axios.post<{ exists: boolean, user?: User }>(`${API_URL}/security-keys/check-serial`,
        { serialNumber: key.serial },
        {
          headers: {
            Authorization: `Bearer ${userInfo.authToken}`,
          },
        }
      );

      if (response.data.exists && response.data.user) {
        const existingUser = response.data.user;
        toast.error(`This YubiKey is already registered to ${existingUser.firstName} ${existingUser.lastName}.`);
        console.log("Key already registered to:", existingUser);
      } else if (response.data.exists) {
        toast.error(`This YubiKey is already registered to another user.`);
      } else {
        setKeyDetails({
          model: key.form_factor,
          type: key.device_type,
          serialNumber: key.serial.toString(),
          pin: ''
        });
        setIsDetectionModalOpen(false);
        setShowKeyDetailsModal(true);
      }
    } catch (error: any) {
      console.error("Error checking serial number:", error);
      toast.error(error.response?.data?.error || "Failed to check YubiKey status.");
    }
  };

  const handleKeyDetailsSubmit = async () => {
    const isUpdate = selectedKey !== null && !isKeyReassigned;
    const isReassignedKey = selectedKey !== null && isKeyReassigned;
    
    if (isUpdate) {
      setIsUpdating(true);
    }
    
    if (!keyDetails.model || !keyDetails.type || !keyDetails.serialNumber) {
      toast.error("Please fill in the required fields");
      return;
    }
    
    if (isReassignedKey && !keyDetails.pin) {
      toast.error("Please provide a PIN for the security key");
      return;
    }

    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");

      if (isReassignedKey) {
        setIsUpdating(true);
        setShowKeyDetailsModal(false);
        setShowRegistrationModal(true);
        sessionStorage.setItem('pendingKeyDetails', JSON.stringify({
          ...keyDetails,
          keyId: selectedKey.id
        }));
        setIsUpdating(false);
        return;
      }

      const endpoint = isUpdate
        ? `${API_URL}/security-keys/${selectedKey.id}`
        : `${API_URL}/security-keys/details`;
      const method = isUpdate ? 'put' : 'post';

      const response = await axios({
        method,
        url: endpoint,
        data: {
          userId: params.id,
          ...keyDetails
        },
        headers: {
          Authorization: `Bearer ${userInfo.authToken}`,
        },
      });

      if (response.data) {
        if (isUpdate) {
          setShowKeyDetailsModal(false);
          fetchSecurityKeys(userInfo.authToken);
          toast.success("Security Key details updated successfully");
        } else {
          setShowKeyDetailsModal(false);
          setShowRegistrationModal(true);
          sessionStorage.setItem('pendingKeyDetails', JSON.stringify(keyDetails));
        }
      }
    } catch (error: any) {
      console.error("Error saving key details:", error);
      toast.error(error.response?.data?.error || "Failed to save key details");
    } finally {
      setIsUpdating(false);
    }
  };

  const handleDeactivate = async () => {
    if (!selectedKey || !deactivationReason.trim()) {
      toast.error("Please provide a reason for deactivation")
      return
    }

    if (!selectedKey.isActive) {
      toast.error("Cannot reactivate a deactivated key")
      return
    }

    try {
      setIsDeactivating(true)
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      if (!userInfo.authToken) {
        toast.error("Authentication required")
        return
      }

      const response = await axios.post<{ message: string }>(
        `${API_URL}/security-keys/${selectedKey.id}/deactivate-status`,
        { reason: deactivationReason },
        {
          headers: {
            Authorization: `Bearer ${userInfo.authToken}`,
          },
        }
      )

      if (response.data) {
        toast.success("Security key deactivated successfully")
        setShowDeactivateDialog(false)
        setDeactivationReason('')
        await fetchSecurityKeys(userInfo.authToken)
        await fetchUserDetails(userInfo.authToken)
      }
    } catch (error: any) {
      console.error("Error deactivating security key:", error)
      toast.error(error.response?.data?.error || "Failed to deactivate security key")
    } finally {
      setIsDeactivating(false)
    }
  }

  const initiateKeyReset = (keyId: number, key: SecurityKey | undefined) => {
    if (!key) return;
    if (!key.credentialId && key.deactivationReason === "Reset by admin") {
      setKeyIdForReassignment(keyId);
      setShowReassignDialog(true);
    } else {
      setKeyIdToReset(keyId);
      setKeyIdForReassignment(keyId);
      setShowResetConfirm(true);
    }
  };

  const handleResetKey = async () => {
    if (!keyIdToReset) return;
    
    try {
      setIsResetting(true);
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
      if (!userInfo.authToken) {
        toast.error("Authentication required");
        return;
      }
      
      const response = await axios.post(
        `${API_URL}/security-keys/${keyIdToReset}/reset`,
        {},
        {
          headers: {
            Authorization: `Bearer ${userInfo.authToken}`,
          },
        }
      );
      
      toast.success("Security key reset successfully");
      setIsKeyReassigned(true);
      setKeyIdForReassignment(keyIdToReset);
      
      await fetchSecurityKeys(userInfo.authToken);
      await fetchUserDetails(userInfo.authToken);
      
    } catch (error: any) {
      console.error("Error resetting security key:", error);
      toast.error(error.response?.data?.error || "Failed to reset security key");
    } finally {
      setIsResetting(false);
      setShowResetConfirm(false);
    }
  };

  const beginRegistration = async () => {
    if (!user) {
      toast.error("User information not available");
      return;
    }
    try {
      setIsRegistering(true);
      
      const storedKeyDetails = JSON.parse(sessionStorage.getItem('pendingKeyDetails') || '{}');
      
      await registerSecurityKey(
        user.username,
        async (message) => {
          toast.success(message);
          setShowRegistrationModal(false);
          
          const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
          await fetchUserDetails(userInfo.authToken);
          await fetchSecurityKeys(userInfo.authToken);
          
          setIsKeyReassigned(false);
          
          sessionStorage.removeItem('pendingKeyDetails');
          setSelectedKey(null);
        },
        (error) => {
          toast.error(error);
        },
        storedKeyDetails,
        isKeyReassigned
      );
    } catch (error) {
      console.error("Error during registration:", error);
      toast.error("Failed to register security key");
    } finally {
      setIsRegistering(false);
    }
  };

  const handleDeleteKey = async () => {
    if (!selectedKey) {
      return
    }

    try {
      setIsDeleting(true)
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}")
      if (!userInfo.authToken) {
        toast.error("Authentication required")
        return
      }

      const response = await axios.delete<{ message: string }>(`${API_URL}/security-keys/${selectedKey.id}`, {
        headers: {
          Authorization: `Bearer ${userInfo.authToken}`,
        },
      })

      if (response.data) {
        toast.success(response.data.message)
        setShowDeleteConfirm(false)
        setSelectedKey(null)
        fetchSecurityKeys(userInfo.authToken)
        fetchUserDetails(userInfo.authToken)
      }
    } catch (error: any) {
      console.error("Error deleting security key:", error)
      toast.error(error.response?.data?.error || "Failed to delete security key")
    } finally {
      setIsDeleting(false)
    }
  }

  const fetchAvailableUsers = async () => {
    try {
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
      if (!userInfo.authToken) {
        toast.error("Authentication required");
        return;
      }
      
      const response = await axios.get(`${API_URL}/users`, {
        headers: {
          Authorization: `Bearer ${userInfo.authToken}`,
        },
      });
      
      interface UsersResponse {
        users: User[];
      }
      
      const responseData = response.data as UsersResponse;
      if (responseData.users) {
        console.log('All users fetched:', responseData.users);
        setUsersList(responseData.users);
      }
    } catch (error) {
      console.error("Error fetching users:", error);
      toast.error("Failed to load available users");
    }
  };

  const handleReassignKey = async () => {
    console.log("Key ID for reassignment:", keyIdForReassignment);
    
    if (!keyIdForReassignment) {
      toast.error("No key selected for reassignment");
      return;
    }
    
    if (!selectedUserId) {
      toast.error("Please select a user to reassign the key to");
      return;
    }
    
    try {
      setIsReassigning(true);
      const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
      if (!userInfo.authToken) {
        toast.error("Authentication required");
        return;
      }
      
      const response = await axios.post(
        `${API_URL}/security-keys/${keyIdForReassignment}/reassign`,
        { new_user_id: selectedUserId },
        {
          headers: {
            Authorization: `Bearer ${userInfo.authToken}`,
          },
        }
      );
      
      interface ReassignResponse {
        message: string;
      }
      
      const responseData = response.data as ReassignResponse;
      toast.success(responseData.message || "Security key reassigned successfully");
      
      await fetchSecurityKeys(userInfo.authToken);
      await fetchUserDetails(userInfo.authToken);
      
    } catch (error: any) {
      console.error("Error reassigning key:", error);
      if (error.response?.data?.error === "New user already has an active security key. Cannot reassign.") {
        toast.error("Failed to reassign key: The selected user already has an active security key.");
      } else {
        toast.error(error.response?.data?.error || "Failed to reassign security key");
      }
    } finally {
      setIsReassigning(false);
      setShowReassignDialog(false);
      setSelectedUserId(null);
      setKeyIdForReassignment(null);
    }
  };

  if (isLoading) {
    return (
        <div className="flex items-center justify-center h-full">
          <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-teal-600"></div>
        </div>
    )
  }

  if (!user) {
    return null
  }

  return (
    <React.Fragment>
      <div className="grid gap-6 w-full font-montserrat">
        <div className="flex justify-between items-center bg-background p-4">
          <div className="flex items-center text-sm text-muted-foreground">
            <span className="hover:text-foreground cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-4 w-4 mx-1" />
            <span className="hover:text-foreground cursor-pointer" onClick={() => router.push("/dashboard/users")}>Users</span>
            <ChevronRight className="h-4 w-4 mx-1" />
            <span className="text-foreground">{user.firstName} {user.lastName}</span>
          </div>
          <Button
              onClick={() => router.push("/dashboard/users")}
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Users
          </Button>
        </div>

        <Card className="shadow-sm">
          <CardHeader>
            <CardTitle>{user.firstName} {user.lastName}'s Information</CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid gap-8">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>First Name</Label>
                  <Input value={user.firstName} disabled/>
                </div>
                <div className="space-y-2">
                  <Label>Last Name</Label>
                  <Input value={user.lastName} disabled/>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Middle Name</Label>
                  <Input value={user.middlename || 'N/A'} disabled/>
                </div>
                <div className="space-y-2">
                  <Label>National ID</Label>
                  <Input value={user.nationalId} disabled/>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Email</Label>
                  <Input value={user.email} disabled/>
                </div>
                <div className="space-y-2">
                  <Label>Username</Label>
                  <Input value={user.username} disabled/>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Role</Label>
                  <Input value={user.role} disabled/>
                </div>
                <div className="space-y-2">
                  <Label>Last Login</Label>
                  <Input
                      value={user.lastLogin
                          ? new Date(user.lastLogin).toLocaleString('en-US', {
                            dateStyle: 'medium',
                            timeStyle: 'short'
                          })
                          : 'Not available'
                      }
                      disabled
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Successful Login Attempts</Label>
                  <Input value={user.loginAttempts} disabled/>
                </div>
                <div className="space-y-2">
                  <Label>Failed Login Attempts</Label>
                  <Input value={user.failedAttempts} disabled/>
                </div>
              </div>

              {user.account_locked && user.locked_time && (
                <div className="grid grid-cols-1 gap-4">
                  <div className="space-y-2">
                    <Label className="text-red-600 dark:text-red-400">Account Locked At</Label>
                    <Input
                      value={
                        new Date(user.locked_time).toLocaleString('en-US', {
                          dateStyle: 'medium',
                          timeStyle: 'short'
                        })
                      }
                      disabled
                      className="border-red-500 dark:border-red-700"
                    />
                  </div>
                </div>
              )}

              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <Label className="text-lg font-semibold">Security Keys</Label>
                </div>

                {securityKeys.length > 0 ? (
                    <SecurityDataTable
                      columns={securityKeyColumns}
                      data={securityKeys}
                      meta={{
                        setSelectedKey,
                        setShowKeyDetailsModal,
                        setKeyDetails,
                        setShowDeactivateDialog,
                        setShowDeleteConfirm,
                        handleResetKey: async (keyId: number) => {
                          initiateKeyReset(keyId, securityKeys.find(k => k.id === keyId)!);
                        },
                        setIsKeyReassigned,
                        setShowRegistrationModal
                      }}
                    />
                ) : (
                    <div className="text-center p-4 border rounded-md bg-muted">
                      <p className="text-muted-foreground">No security keys registered yet</p>
                      <Button
                          onClick={() => setIsDetectionModalOpen(true)}
                          className="mt-2"
                      >
                        <Key className="h-4 w-4 mr-1"/>
                        Register Security Key
                      </Button>
                    </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Key Details Modal */}
        <Dialog open={showKeyDetailsModal} onOpenChange={setShowKeyDetailsModal}>
          <DialogContent className="sm:max-w-md font-montserrat">
            <DialogHeader>
              <DialogTitle>
                {selectedKey 
                  ? isKeyReassigned 
                    ? 'Prepare Security Key for Registration' 
                    : 'Edit Security Key'
                  : 'Security Key Details'
                }
              </DialogTitle>
              <DialogDescription>
                {selectedKey 
                  ? isKeyReassigned
                    ? 'Confirm the details of the security key before registering it for the new user'
                    : 'Update the details of the security key'
                  : 'Enter the details of the security key before registration'
                }
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {isKeyReassigned && (
                <div className="bg-blue-50 dark:bg-transparent p-3 rounded-sm border border-blue-400 dark:border-blue-600 mb-4">
                  <h4 className="text-blue-800 dark:text-blue-300 font-medium">Reassigned Security Key</h4>
                  <p className="text-blue-700 dark:text-blue-400 text-sm mt-1">
                    This key has been reset and is ready to be registered for this user. Review the details below.
                  </p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="model">Security Key Model</Label>
                <Select
                  value={keyDetails.model}
                  onValueChange={(value) => {
                    setKeyDetails({
                      ...keyDetails,
                      model: value,
                      type: '' // Reset type when model changes
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
                <Label htmlFor="type">Key Type</Label>
                <Select
                  value={keyDetails.type}
                  onValueChange={(value) => setKeyDetails({ ...keyDetails, type: value })}
                  disabled={!keyDetails.model}
                >
                  <SelectTrigger className="w-full border border-input">
                    <SelectValue placeholder="Select Type" />
                  </SelectTrigger>
                  <SelectContent className="w-full min-w-[300px]">
                    <SelectGroup>
                      {keyDetails.model && securityKeyModels[keyDetails.model as keyof typeof securityKeyModels].map((type) => (
                        <SelectItem key={type} value={type}>
                          {type}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="serialNumber">Serial Number</Label>
                <Input
                    id="serialNumber"
                    type="number"
                    placeholder="Enter serial number"
                    value={keyDetails.serialNumber}
                    onChange={(e) => setKeyDetails({ ...keyDetails, serialNumber: e.target.value })}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="pin">
                  Security Key PIN
                  {!selectedKey && <span className="text-red-500 ml-1">*</span>}
                  {selectedKey && !isKeyReassigned && <span className="text-gray-400 ml-2 text-sm">(Leave blank to keep current PIN)</span>}
                  {isKeyReassigned && <span className="text-red-500 ml-1">*</span>}
                </Label>
                <Input
                    id="pin"
                    type="password"
                    placeholder={selectedKey && !isKeyReassigned ? "Enter new PIN (optional)" : "Enter security key PIN"}
                    value={keyDetails.pin}
                    onChange={(e) => setKeyDetails({ ...keyDetails, pin: e.target.value })}
                    required={!selectedKey || isKeyReassigned}
                />
              </div>
            </div>

            <DialogFooter>
              <Button
                  variant="outline"
                  type="button"
                  onClick={() => {
                    setShowKeyDetailsModal(false);
                    setKeyDetails({
                      model: '',
                      type: '',
                      serialNumber: '',
                      pin: ''
                    });
                    setSelectedKey(null);
                    setIsKeyReassigned(false); // Reset this flag
                  }}
              >
                Cancel
              </Button>
              <Button
                  onClick={handleKeyDetailsSubmit}
                  disabled={isUpdating}
              >
                  {selectedKey ? (
                    isKeyReassigned ? (
                      isUpdating ? (
                        <>
                          <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                          Preparing...
                        </>
                      ) : "Continue to Registration"
                    ) : (
                      isUpdating ? (
                        <>
                          <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                          Updating...
                        </>
                      ) : "Update"
                    )
                  ) : "Save and Continue"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Security Key Registration Modal */}
        <Dialog open={showRegistrationModal} onOpenChange={setShowRegistrationModal}>
          <DialogContent className="sm:max-w-md font-montserrat">
            <DialogHeader>
              <DialogTitle>{isKeyReassigned ? 'Register Reassigned Security Key' : 'Register Security Key'}</DialogTitle>
              <DialogDescription>
                Connect your security key to protect {user?.firstName} {user?.lastName}'s account against unauthorized access
                and phishing attacks.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="bg-yellow-50 dark:bg-transparent p-3 rounded-sm border border-yellow-400 dark:border-yellow-600">
                <h4 className="text-yellow-800 dark:text-yellow-300 font-medium">Important Instructions</h4>
                <ul className="list-disc text-left pl-5 mt-1 text-sm text-yellow-700 dark:text-yellow-400 space-y-1">
                  <li>Ensure the security key is connected to your device</li>
                  <li>When prompted, tap the button on your security key</li>
                  <li>Keep the key connected until registration is complete</li>
                </ul>
              </div>
              
              {isKeyReassigned && (
                <div className="bg-red-50 dark:bg-transparent p-3 rounded-sm border border-red-400 dark:border-red-600 mt-3">
                  <h4 className="text-red-800 dark:text-red-300 font-medium">Reassigned Security Key</h4>
                  <p className="text-red-700 dark:text-red-400 text-sm mt-1">
                    This security key was reassigned from another user. It needs to be registered with this account before it can be used.
                  </p>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button
                  variant="outline"
                  type="button"
                  onClick={() => {
                    setShowRegistrationModal(false);
                    setIsKeyReassigned(false); // Reset the flag when canceling
                  }}
                  disabled={isRegistering}
              >
                Cancel
              </Button>
              <Button
                  onClick={beginRegistration}
                  disabled={isRegistering}
              >
                {isRegistering ? (
                    <>
                      <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                      Registering...
                    </>
                ) : (
                    "Begin Registration"
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Deactivate Security Key Dialog */}
        <Dialog open={showDeactivateDialog} onOpenChange={setShowDeactivateDialog}>
          <DialogContent className="sm:max-w-md font-montserrat">
            <DialogHeader>
              <DialogTitle>Deactivate Security Key</DialogTitle>
              <DialogDescription>
                Please provide a reason for deactivating this security key. This will be stored for audit purposes.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {selectedKey && (
                <div className="bg-muted p-3 rounded border mb-4">
                  <p><strong>Model:</strong> {selectedKey.model || 'N/A'}</p>
                  <p><strong>Type:</strong> {selectedKey.type || 'N/A'}</p>
                  <p><strong>Serial Number:</strong> {selectedKey.serialNumber || 'N/A'}</p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="deactivationReason">Deactivation Reason</Label>
                <Input
                  aria-placeholder="Enter the reason for deactivation"
                  value={deactivationReason}
                  onChange={(e) => setDeactivationReason(e.target.value)}
                  className="min-h-[100px]"
                />
              </div>
            </div>

            <DialogFooter>
              <Button
                variant="outline"
                type="button"
                onClick={() => {
                  setShowDeactivateDialog(false)
                  setDeactivationReason('')
                  setSelectedKey(null)
                }}
              >
                Cancel
              </Button>
              <Button
                onClick={handleDeactivate}
                disabled={isDeactivating || !deactivationReason.trim()}
              >
                {isDeactivating ? (
                  <>
                    <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                    Deactivating...
                  </>
                ) : (
                  "Deactivate"
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete Confirmation Dialog */}
        <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
          <AlertDialogContent className="font-montserrat">
            <AlertDialogHeader>
              <AlertDialogTitle>Delete Security Key</AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to delete this security key? This action cannot be undone and the user
                will no longer be able to use this key for authentication.
                {selectedKey && (
                    <div className="bg-muted p-3 mt-2 rounded border">
                      <div><strong>Model:</strong> {selectedKey.model || 'N/A'}</div>
                      <div><strong>Type:</strong> {selectedKey.type || 'N/A'}</div>
                      <div><strong>Status:</strong> {selectedKey.isActive ? 'Active' : 'Inactive'}</div>
                    </div>
                )}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel onClick={() => {
                setShowDeleteConfirm(false);
                setSelectedKey(null);
              }}>
                Cancel
              </AlertDialogCancel>
              <AlertDialogAction
                  onClick={handleDeleteKey}
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

        <AlertDialog open={showResetConfirm} onOpenChange={setShowResetConfirm}>
        <AlertDialogContent className="font-montserrat">
          <AlertDialogHeader>
            <AlertDialogTitle>Reset Security Key</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="text-muted-foreground text-sm">
                <div className="space-y-4">
                  <p>Are you sure you want to reset this security key for reassignment to another user?</p>
                  
                  <div className="bg-yellow-50 p-4 rounded-md border border-yellow-200 dark:bg-transparent dark:border-yellow-700/40">
                    <h3 className="font-semibold text-yellow-800 dark:text-yellow-300">This will:</h3>
                    <ul className="list-disc pl-5 text-sm text-yellow-700 dark:text-yellow-400 space-y-1">
                      <li>Deactivate the key for the current user</li>
                      <li>Clear the security key's PIN in the database</li>
                      <li>Mark the key as available for reassignment</li>
                    </ul>
                  </div>
                  
                  <div className="bg-red-50 p-4 rounded-md border border-red-200 dark:bg-transparent dark:border-red-700/40">
                    <h3 className="font-semibold text-red-800 dark:text-red-300">Note:</h3>
                    <p className="text-sm text-red-700 dark:text-red-400">
                      For security reasons, after resetting, a new user will need to register
                      the security key before they can use it.
                    </p>
                  </div>
                </div>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel 
              onClick={() => {
                setShowResetConfirm(false);
                setKeyIdToReset(null);
              }}
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                handleResetKey().then(() => {
                  setShowReassignDialog(true);
                });
              }}
              disabled={isResetting}
            >
              {isResetting ? (
                <>
                  <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                  Resetting...
                </>
              ) : (
                "Reset Key"
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>


      <Dialog open={showReassignDialog} onOpenChange={setShowReassignDialog}>
        <DialogContent className="sm:max-w-md font-montserrat">
          <DialogHeader>
            <DialogTitle>Reassign Security Key</DialogTitle>
            <DialogDescription>
              Select a user to reassign this security key to.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {selectedKey && (
              <div className="bg-muted p-3 rounded border mb-4">
                <p><strong>Model:</strong> {selectedKey.model || 'N/A'}</p>
                <p><strong>Type:</strong> {selectedKey.type || 'N/A'}</p>
                <p><strong>Serial Number:</strong> {selectedKey.serialNumber || 'N/A'}</p>
                {/* <p className="mt-2 text-amber-600">
                  {selectedKey.isActive 
                    ? "This key is currently active. You must reset it before reassigning." 
                    : "This key is ready for reassignment."}
                </p> */}
              </div>
            )}

            <div className="space-y-2">
              <Label htmlFor="newUser">Assign to User</Label>
              <Select 
                value={selectedUserId?.toString() || ""}
                onValueChange={(value) => setSelectedUserId(parseInt(value))}
              >
                <SelectTrigger className="w-full border border-input">
                  <SelectValue placeholder="Select a user" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {usersList.map((user) => (
                      <SelectItem key={user.id} value={user.id.toString()}>
                        {user.firstName} {user.lastName} ({user.username})
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              type="button"
              onClick={() => {
                setShowReassignDialog(false);
                setSelectedUserId(null);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleReassignKey}
              disabled={isReassigning || !selectedUserId}
            >
              {isReassigning ? (
                <>
                  <span className="animate-spin rounded-xl h-4 w-4 border-b-2 border-white mr-2"></span>
                  Reassigning...
                </>
              ) : "Reassign Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </div>
      <YubiKeyDetectionModal
        isOpen={isDetectionModalOpen}
        onClose={() => setIsDetectionModalOpen(false)}
        onSelect={handleSelectYubiKey}
      />
    </React.Fragment>
  )
}
