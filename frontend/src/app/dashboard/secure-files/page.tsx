"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuthStore } from "@/store/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DataTable } from "@/components/data-table/data-table";
import { secureFilesColumns, EncryptedFile } from "./secure-files-columns";
import { FileUploadDialog } from "./file-upload-dialog";
import { VaultCard, Vault } from "./vault-card";
import { CreateVaultDialog } from "./create-vault-dialog";
import { UploadFolderDialog } from "./upload-folder-dialog";
import { MoveToVaultDialog } from "./move-to-vault-dialog";
import {
  Upload,
  RefreshCw,
  FileKey,
  Shield,
  Search,
  AlertCircle,
  FolderKey,
  FolderOpen,
  ChevronRight,
  Pencil,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { API_URL } from "@/app/utils/constants";
import { DownloadDetectionDialog } from "@/components/secure-files/download-detection-dialog";

interface SecurityKey {
  id: number;
  serial_number: number | null;
  device_type: string | null;
  form_factor: string | null;
}

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

export default function SecureFilesPage() {
  // ── Auth / user ──────────────────────────────────────────────────────────
  const { user: authUser, _hasHydrated } = useAuthStore();
  const authToken = authUser?.authToken ?? null;
  const [users, setUsers] = useState<User[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);

  // ── Vault state ──────────────────────────────────────────────────────────
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [activeVault, setActiveVault] = useState<Vault | null>(null);
  const [vaultToDelete, setVaultToDelete] = useState<Vault | null>(null);
  const [vaultToRename, setVaultToRename] = useState<Vault | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [isRenaming, setIsRenaming] = useState(false);

  // ── File state ───────────────────────────────────────────────────────────
  const [files, setFiles] = useState<EncryptedFile[]>([]);
  const [ungroupedFiles, setUngroupedFiles] = useState<EncryptedFile[]>([]);
  const [securityKeys, setSecurityKeys] = useState<SecurityKey[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [fileToDelete, setFileToDelete] = useState<EncryptedFile | null>(null);
  const [fileToDownload, setFileToDownload] = useState<EncryptedFile | null>(null);
  const [fileToMove, setFileToMove] = useState<EncryptedFile | null>(null);

  // ── Dialog open state ────────────────────────────────────────────────────
  const [isUploadDialogOpen, setIsUploadDialogOpen] = useState(false);
  const [isCreateVaultOpen, setIsCreateVaultOpen] = useState(false);
  const [isUploadFolderOpen, setIsUploadFolderOpen] = useState(false);

  // ─────────────────────────────────────────────────────────────────────────

  const fetchUsers = useCallback(async () => {
    if (!authToken) return;
    try {
      const res = await fetch(`${API_URL}/users`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } catch { /* silent */ }
  }, [authToken]);

  const fetchVaults = useCallback(async () => {
    if (!authToken) return;
    try {
      let url = `${API_URL}/vaults`;
      if (selectedUserId) url += `?user_id=${selectedUserId}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        setVaults(data.vaults || []);
      }
    } catch { toast.error("Failed to load vaults"); }
  }, [authToken, selectedUserId]);

  const fetchFiles = useCallback(async () => {
    if (!_hasHydrated) return;
    if (!authToken) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    try {
      // Inside a vault
      if (activeVault) {
        let url = `${API_URL}/files?vault_id=${activeVault.id}`;
        if (selectedUserId) url += `&user_id=${selectedUserId}`;
        const res = await fetch(url, { headers: { Authorization: `Bearer ${authToken}` } });
        if (!res.ok) throw new Error();
        const data = await res.json();
        setFiles(data.files || []);
        return;
      }
      // Root: ungrouped files
      let url = `${API_URL}/files?ungrouped=true`;
      if (selectedUserId) url += `&user_id=${selectedUserId}`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${authToken}` } });
      if (!res.ok) throw new Error();
      const data = await res.json();
      setUngroupedFiles(data.files || []);
    } catch {
      toast.error("Failed to load files");
    } finally {
      setIsLoading(false);
    }
  }, [authToken, selectedUserId, activeVault, _hasHydrated]);

  const fetchSecurityKeys = useCallback(async () => {
    if (!authToken) return;
    try {
      let url = `${API_URL}/files/user-security-keys`;
      if (selectedUserId) url += `?user_id=${selectedUserId}`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${authToken}` } });
      if (res.ok) {
        const data = await res.json();
        setSecurityKeys(data.security_keys || []);
      }
    } catch { /* silent */ }
  }, [authToken, selectedUserId]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  useEffect(() => {
    fetchVaults();
    fetchFiles();
    fetchSecurityKeys();
  }, [fetchVaults, fetchFiles, fetchSecurityKeys]);

  // ── Filtered files for table ─────────────────────────────────────────────
  const displayFiles = activeVault ? files : ungroupedFiles;
  const filteredFiles = searchQuery.trim() === ""
    ? displayFiles
    : displayFiles.filter(
      (f) =>
        f.original_filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
        f.mime_type?.toLowerCase().includes(searchQuery.toLowerCase())
    );

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleDownload = async (file: EncryptedFile, keyId: number) => {

    try {
      const res = await fetch(`${API_URL}/files/${file.id}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
          "X-Security-Key-ID": keyId.toString(),
        },
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to download file");
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = file.original_filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success("File downloaded successfully");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to download file");
    }
  };

  const handlePreview = async (file: EncryptedFile) => {

    try {
      const res = await fetch(`${API_URL}/files/${file.id}/preview`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to preview file");
      }
      const blob = await res.blob();
      window.open(window.URL.createObjectURL(blob), "_blank");
      toast.success("Preview loaded");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to preview file");
    }
  };

  const handleDeleteFile = async () => {
    if (!fileToDelete) return;

    try {
      const res = await fetch(`${API_URL}/files/${fileToDelete.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error("Failed to delete file");
      toast.success("File deleted");
      fetchFiles();
      fetchVaults();
    } catch {
      toast.error("Failed to delete file");
    } finally {
      setFileToDelete(null);
    }
  };

  const handleDeleteVault = async () => {
    if (!vaultToDelete) return;

    try {
      const res = await fetch(`${API_URL}/vaults/${vaultToDelete.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (!res.ok) throw new Error();
      toast.success(`Vault "${vaultToDelete.name}" deleted`);
      fetchVaults();
      fetchFiles();
    } catch {
      toast.error("Failed to delete vault");
    } finally {
      setVaultToDelete(null);
    }
  };

  const handleRenameVault = async () => {
    if (!vaultToRename || !renameValue.trim()) return;

    setIsRenaming(true);
    try {
      const res = await fetch(`${API_URL}/vaults/${vaultToRename.id}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name: renameValue.trim() }),
      });
      if (!res.ok) throw new Error();
      toast.success("Vault renamed");
      fetchVaults();
      if (activeVault?.id === vaultToRename.id) {
        setActiveVault((v) => v ? { ...v, name: renameValue.trim() } : v);
      }
    } catch {
      toast.error("Failed to rename vault");
    } finally {
      setIsRenaming(false);
      setVaultToRename(null);
      setRenameValue("");
    }
  };

  const refresh = () => {
    fetchVaults();
    fetchFiles();
    fetchSecurityKeys();
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const totalFilesSize = (activeVault ? files : ungroupedFiles).reduce(
    (sum, f) => sum + f.file_size,
    0
  );
  const allFilesCount = vaults.reduce((sum, v) => sum + v.file_count, 0) + ungroupedFiles.length;

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div className="container mx-auto p-6 space-y-6 font-montserrat">
      {/* ── Page Header ── */}
      <div className="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
        <div>
          {/* Breadcrumb */}
          <div className="flex items-center gap-1 text-sm text-muted-foreground mb-1">
            <button
              className="hover:text-foreground transition-colors flex items-center gap-1"
              onClick={() => setActiveVault(null)}
            >
              <FileKey className="h-4 w-4" />
              Secure Files
            </button>
            {activeVault && (
              <>
                <ChevronRight className="h-3 w-3" />
                <span className="text-foreground font-medium">{activeVault.name}</span>
              </>
            )}
          </div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            {activeVault ? (
              <><FolderKey className="h-8 w-8" />{activeVault.name}</>
            ) : (
              <><FileKey className="h-8 w-8" />Secure Files</>
            )}
          </h1>
          <p className="text-muted-foreground mt-1">
            {activeVault
              ? "Encrypted files in this vault"
              : "Encrypted file storage protected by security keys"}
          </p>
        </div>

        <div className="flex gap-2 w-full md:w-auto flex-wrap">
          {authUser?.role === "admin" && (
            <Select
              value={selectedUserId?.toString() || "all"}
              onValueChange={(v) => {
                setSelectedUserId(v === "all" ? null : parseInt(v));
                setActiveVault(null);
              }}
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Select User" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">My Files</SelectItem>
                {users
                  .filter((u) => u.id !== authUser?.id)
                  .map((u) => (
                    <SelectItem key={u.id} value={u.id.toString()}>
                      {u.username}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          )}

          <Button variant="outline" onClick={refresh}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>

          {!activeVault && (
            <>
              <Button variant="outline" onClick={() => setIsUploadFolderOpen(true)}>
                <FolderOpen className="mr-2 h-4 w-4" />
                Upload Folder
              </Button>
              <Button variant="outline" onClick={() => setIsCreateVaultOpen(true)}>
                <FolderKey className="mr-2 h-4 w-4" />
                New Vault
              </Button>
            </>
          )}

          <Button onClick={() => setIsUploadDialogOpen(true)}>
            <Upload className="mr-2 h-4 w-4" />
            Upload File
          </Button>
        </div>
      </div>

      {/* ── Stats Cards ── */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Files</CardTitle>
            <FileKey className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {activeVault ? files.length : allFilesCount}
            </div>
            <p className="text-xs text-muted-foreground">
              {formatFileSize(totalFilesSize)} total
            </p>
          </CardContent>
        </Card>

        {!activeVault && (
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Vaults</CardTitle>
              <FolderKey className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{vaults.length}</div>
              <p className="text-xs text-muted-foreground">Named containers</p>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Security Keys</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{securityKeys.length}</div>
            <p className="text-xs text-muted-foreground">Available for encryption</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Encryption</CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">AES-256-GCM</div>
            <p className="text-xs text-muted-foreground">Military-grade encryption</p>
          </CardContent>
        </Card>
      </div>

      {/* ── No Keys Warning ── */}
      {securityKeys.length === 0 && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>No Active Security Keys</AlertTitle>
          <AlertDescription>
            You need at least one active security key to upload and encrypt files.
            Please register a security key first.
          </AlertDescription>
        </Alert>
      )}

      {/* ── Vault Grid (root view) ── */}
      {!activeVault && (
        <>
          {vaults.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold">Vaults</h2>
              <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
                {vaults.map((vault) => (
                  <VaultCard
                    key={vault.id}
                    vault={vault}
                    onClick={setActiveVault}
                    onRename={(v) => {
                      setVaultToRename(v);
                      setRenameValue(v.name);
                    }}
                    onDelete={setVaultToDelete}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Ungrouped Files */}
          <Card>
            <CardHeader>
              <CardTitle>Ungrouped Files</CardTitle>
              <CardDescription>Files not assigned to any vault</CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
                  <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
                  <span>Loading files...</span>
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-4 mb-4">
                    <div className="relative flex-1 max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search files..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-9"
                      />
                    </div>
                  </div>
                  <DataTable
                    columns={secureFilesColumns({
                      onPreview: handlePreview,
                      onDownload: (file) => setFileToDownload(file),
                      onDelete: (file) => setFileToDelete(file),
                      onMoveToVault: (file) => setFileToMove(file),
                    })}
                    data={filteredFiles}
                  />
                </>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* ── Vault Detail (drill-in view) ── */}
      {activeVault && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FolderKey className="h-5 w-5" />
              {activeVault.name}
            </CardTitle>
            <CardDescription>
              All files are encrypted at rest using your security key
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex flex-col items-center space-y-2 text-muted-foreground py-8">
                <div className="animate-spin rounded-xl h-8 w-8 border-b-2 border-primary"></div>
                <span>Loading files...</span>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-4 mb-4">
                  <div className="relative flex-1 max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search files..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-9"
                    />
                  </div>
                </div>
                <DataTable
                  columns={secureFilesColumns({
                    onPreview: handlePreview,
                    onDownload: (file) => setFileToDownload(file),
                    onDelete: (file) => setFileToDelete(file),
                    onMoveToVault: (file) => setFileToMove(file),
                  })}
                  data={filteredFiles}
                />
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* ── Dialogs ── */}
      <FileUploadDialog
        open={isUploadDialogOpen}
        onOpenChange={setIsUploadDialogOpen}
        securityKeys={securityKeys}
        vaultId={activeVault?.id}
        userId={selectedUserId}
        onUploadComplete={() => {
          setIsUploadDialogOpen(false);
          fetchFiles();
          fetchVaults();
        }}
      />

      <CreateVaultDialog
        open={isCreateVaultOpen}
        onOpenChange={setIsCreateVaultOpen}
        userId={selectedUserId}
        onCreated={(vault) => {
          setVaults((prev) => [vault, ...prev]);
          setActiveVault(vault);
        }}
      />

      <UploadFolderDialog
        open={isUploadFolderOpen}
        onOpenChange={setIsUploadFolderOpen}
        userId={selectedUserId}
        onUploadComplete={() => {
          setIsUploadFolderOpen(false);
          fetchVaults();
          fetchFiles();
        }}
      />

      {/* Delete file */}
      <AlertDialog open={!!fileToDelete} onOpenChange={() => setFileToDelete(null)}>
        <AlertDialogContent className="font-montserrat">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Encrypted File</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{fileToDelete?.original_filename}&quot;?
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteFile} className="bg-red-600 hover:bg-red-700">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete vault */}
      <AlertDialog open={!!vaultToDelete} onOpenChange={() => setVaultToDelete(null)}>
        <AlertDialogContent className="font-montserrat">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Vault</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &quot;{vaultToDelete?.name}&quot;? The files inside
              will become ungrouped, they will not be deleted.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteVault} className="bg-red-600 hover:bg-red-700">
              Delete Vault
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Rename vault */}
      <Dialog open={!!vaultToRename} onOpenChange={() => setVaultToRename(null)}>
        <DialogContent className="sm:max-w-[380px] font-montserrat">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Pencil className="h-4 w-4" />
              Rename Vault
            </DialogTitle>
          </DialogHeader>
          <div className="py-2 space-y-1.5">
            <Label htmlFor="rename-input">New name</Label>
            <Input
              id="rename-input"
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleRenameVault()}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setVaultToRename(null)} disabled={isRenaming}>
              Cancel
            </Button>
            <Button onClick={handleRenameVault} disabled={!renameValue.trim() || isRenaming}>
              Rename
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Download dialog */}
      <DownloadDetectionDialog
        file={fileToDownload}
        open={!!fileToDownload}
        onOpenChange={(open) => !open && setFileToDownload(null)}
        onDownloadReady={(file, keyId) => {
          handleDownload(file, keyId);
          setFileToDownload(null);
        }}
      />

      {/* Move to vault dialog */}
      <MoveToVaultDialog
        file={fileToMove}
        vaults={vaults}
        open={!!fileToMove}
        onOpenChange={(open) => !open && setFileToMove(null)}
        onMoved={() => {
          fetchFiles();
          fetchVaults();
        }}
      />
    </div>
  );
}
