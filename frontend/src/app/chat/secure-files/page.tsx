"use client";

import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DataTable } from "@/components/data-table/data-table";
// Reuse components from dashboard
import { secureFilesColumns, EncryptedFile } from "../../dashboard/secure-files/secure-files-columns";
import { FileUploadDialog } from "../../dashboard/secure-files/file-upload-dialog";
import { Header } from "@/components/header";
import { Upload, RefreshCw, FileKey, Shield, Search, Download, AlertCircle } from "lucide-react";
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
import { useRouter } from "next/navigation";
import { API_URL } from "@/app/utils/constants";
import { DownloadDetectionDialog } from "@/components/secure-files/download-detection-dialog";

interface SecurityKey {
  id: number;
  serial_number: number | null;
  device_type: string | null;
  form_factor: string | null;
}

export default function SecureFilesPage() {
  const router = useRouter();
  const [files, setFiles] = useState<EncryptedFile[]>([]);
  const [filteredFiles, setFilteredFiles] = useState<EncryptedFile[]>([]);
  const [securityKeys, setSecurityKeys] = useState<SecurityKey[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [isUploadDialogOpen, setIsUploadDialogOpen] = useState(false);
  const [fileToDelete, setFileToDelete] = useState<EncryptedFile | null>(null);
  const [fileToDownload, setFileToDownload] = useState<EncryptedFile | null>(null);

  const getAuthToken = useCallback(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    return userInfo.authToken || null;
  }, []);

  // Check auth on mount
  useEffect(() => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    if (!userInfo || !userInfo.authToken) {
      router.push("/");
    }
  }, [router]);

  const fetchFiles = useCallback(async () => {
    const authToken = getAuthToken();
    if (!authToken) return;
    
    setIsLoading(true);
    try {
      const response = await fetch(`${API_URL}/files`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch files");
      }

      const data = await response.json();
      setFiles(data.files || []);
      setFilteredFiles(data.files || []);
    } catch (error) {
      console.error("Error fetching files:", error);
      toast.error("Failed to load files");
    } finally {
      setIsLoading(false);
    }
  }, [getAuthToken]);

  const fetchSecurityKeys = useCallback(async () => {
    const authToken = getAuthToken();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${API_URL}/files/user-security-keys`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch security keys");
      }

      const data = await response.json();
      setSecurityKeys(data.security_keys || []);
    } catch (error) {
      console.error("Error fetching security keys:", error);
      toast.error("Failed to load security keys");
    }
  }, [getAuthToken]);

  useEffect(() => {
    fetchFiles();
    fetchSecurityKeys();
  }, [fetchFiles, fetchSecurityKeys]);

  useEffect(() => {
    if (searchQuery.trim() === "") {
      setFilteredFiles(files);
    } else {
      const query = searchQuery.toLowerCase();
      const filtered = files.filter(
        (file) =>
          file.original_filename.toLowerCase().includes(query) ||
          file.mime_type?.toLowerCase().includes(query)
      );
      setFilteredFiles(filtered);
    }
  }, [searchQuery, files]);

  const handleDownload = async (file: EncryptedFile, keyId: number) => {
    const authToken = getAuthToken();
    try {
      const response = await fetch(`${API_URL}/files/${file.id}`, {
        headers: {
          Authorization: `Bearer ${authToken}`,
          "X-Security-Key-ID": keyId.toString(),
        },
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to download file");
      }

      const blob = await response.blob();
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
      console.error("Error downloading file:", error);
      toast.error(error instanceof Error ? error.message : "Failed to download file");
    }
  };

  const handleDelete = async () => {
    if (!fileToDelete) return;

    const authToken = getAuthToken();
    try {
      const response = await fetch(`${API_URL}/files/${fileToDelete.id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to delete file");
      }

      toast.success("File deleted successfully");
      fetchFiles();
    } catch (error) {
      console.error("Error deleting file:", error);
      toast.error("Failed to delete file");
    } finally {
      setFileToDelete(null);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const totalFilesSize = files.reduce((sum, file) => sum + file.file_size, 0);

  return (
    <div className="h-dvh flex flex-col font-montserrat w-full">
      <Header />
      <div className="container mx-auto p-6 space-y-6 overflow-y-auto flex-1 pt-24">
        {/* Page Header */}
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <FileKey className="h-8 w-8" />
              Secure Files
            </h1>
            <p className="text-muted-foreground mt-1">
              Encrypted file storage protected by your security key
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={fetchFiles} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button onClick={() => setIsUploadDialogOpen(true)} disabled={securityKeys.length === 0}>
              <Upload className="h-4 w-4 mr-2" />
              Upload File
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Files</CardTitle>
              <FileKey className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{files.length}</div>
              <p className="text-xs text-muted-foreground">
                {formatFileSize(totalFilesSize)} total
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Security Keys</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{securityKeys.length}</div>
              <p className="text-xs text-muted-foreground">
                Available for encryption
              </p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Encryption</CardTitle>
              <Shield className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">AES-256-GCM</div>
              <p className="text-xs text-muted-foreground">
                Military-grade encryption
              </p>
            </CardContent>
          </Card>
        </div>

        {/* No Security Keys Warning */}
        {securityKeys.length === 0 && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>No Active Security Keys</AlertTitle>
            <AlertDescription>
              You need at least one active security key to upload and encrypt files.
              Please register a security key in Settings first.
            </AlertDescription>
          </Alert>
        )}

        {/* Files Table */}
        <Card>
          <CardHeader>
            <CardTitle>My Encrypted Files</CardTitle>
            <CardDescription>
              All files are encrypted at rest using your security key
            </CardDescription>
          </CardHeader>
          <CardContent>
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
              onDownload: (file: EncryptedFile) => {
                setFileToDownload(file);
              },
                onDelete: (file: EncryptedFile) => setFileToDelete(file),
              })}
              data={filteredFiles}
            />
          </CardContent>
        </Card>

        {/* Upload Dialog */}
        <FileUploadDialog
          open={isUploadDialogOpen}
          onOpenChange={setIsUploadDialogOpen}
          securityKeys={securityKeys}
          onUploadComplete={() => {
            fetchFiles();
            setIsUploadDialogOpen(false);
          }}
        />

        {/* Delete Confirmation Dialog */}
        <AlertDialog open={!!fileToDelete} onOpenChange={() => setFileToDelete(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete Encrypted File</AlertDialogTitle>
              <AlertDialogDescription>
                Are you sure you want to delete &quot;{fileToDelete?.original_filename}&quot;?
                This action cannot be undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={handleDelete} className="bg-red-600 hover:bg-red-700">
                Delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        {/* Automated Download Detection Dialog */}
        <DownloadDetectionDialog
          file={fileToDownload}
          open={!!fileToDownload}
          onOpenChange={(open: boolean) => !open && setFileToDownload(null)}
          onDownloadReady={(file: EncryptedFile, keyId: number) => {
            handleDownload(file, keyId);
            setFileToDownload(null);
          }}
        />
      </div>
    </div>
  );
}
