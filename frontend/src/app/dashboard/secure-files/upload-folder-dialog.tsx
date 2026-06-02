"use client";

import { useState, useCallback, useRef } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { FolderOpen, Loader2, CheckCircle2, AlertCircle, FolderKey } from "lucide-react";
import { toast } from "sonner";
import { API_URL } from "@/app/utils/constants";
import { useYubiKeyDetection } from "@/app/hooks/use-yubikey-detection";
import { KeyDetectionOverlay } from "@/components/secure-files/key-detection-overlay";

interface UploadFolderDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUploadComplete: () => void;
  userId?: number | null;
}

type UploadState = "idle" | "uploading" | "done" | "error";

export function UploadFolderDialog({
  open,
  onOpenChange,
  onUploadComplete,
  userId,
}: UploadFolderDialogProps) {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [vaultName, setVaultName] = useState("");
  const [uploadState, setUploadState] = useState<UploadState>("idle");
  const [progress, setProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState("");
  const folderInputRef = useRef<HTMLInputElement>(null);

  const { detectedKeys, isConnected, isVerifying } = useYubiKeyDetection(open);
  const matchedKey = detectedKeys.find((k) => k.id !== undefined);

  const handleFolderChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = Array.from(e.target.files || []);
      if (files.length === 0) return;
      setSelectedFiles(files);
      // Derive vault name from the common top-level folder
      const folderName =
        files[0].webkitRelativePath.split("/")[0] || "Uploaded Folder";
      setVaultName(folderName);
    },
    []
  );

  const reset = () => {
    setSelectedFiles([]);
    setVaultName("");
    setUploadState("idle");
    setProgress(0);
    setErrorMessage("");
    if (folderInputRef.current) folderInputRef.current.value = "";
  };

  const handleClose = () => {
    if (uploadState !== "uploading") {
      reset();
      onOpenChange(false);
    }
  };

  const handleUpload = async () => {
    if (!selectedFiles.length || !matchedKey?.id || !vaultName.trim()) return;

    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    const authToken = userInfo.authToken;
    if (!authToken) return;

    setUploadState("uploading");
    setProgress(0);
    setErrorMessage("");

    try {
      // 1. Create the vault
      const vaultRes = await fetch(`${API_URL}/vaults`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: vaultName.trim(),
          ...(userId != null && { owner_user_id: userId }),
        }),
      });
      if (!vaultRes.ok) {
        const err = await vaultRes.json();
        throw new Error(err.error || "Failed to create vault");
      }
      const { vault } = await vaultRes.json();

      // 2. Upload each file into the vault
      let done = 0;
      for (const file of selectedFiles) {
        const formData = new FormData();
        formData.append("file", file);
        formData.append("security_key_id", matchedKey.id.toString());
        formData.append("vault_id", vault.id.toString());
        if (userId) formData.append("user_id", userId.toString());

        const res = await fetch(`${API_URL}/files/upload`, {
          method: "POST",
          headers: { Authorization: `Bearer ${authToken}` },
          body: formData,
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || `Failed to upload ${file.name}`);
        }
        done++;
        setProgress(Math.round((done / selectedFiles.length) * 100));
      }

      setUploadState("done");
      toast.success(
        `Vault "${vault.name}" created with ${selectedFiles.length} file${selectedFiles.length !== 1 ? "s" : ""}`
      );
      setTimeout(() => {
        reset();
        onUploadComplete();
      }, 1200);
    } catch (error) {
      setUploadState("error");
      setErrorMessage(
        error instanceof Error ? error.message : "Upload failed"
      );
      toast.error("Folder upload failed");
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px] font-montserrat">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderKey className="h-5 w-5 text-primary" />
            Upload Folder as Vault
          </DialogTitle>
          <DialogDescription>
            Select a local folder. All files will be encrypted and stored in a
            new vault named after the folder.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Key detection */}
          <KeyDetectionOverlay
            detectedKey={
              matchedKey || (detectedKeys.length > 0 ? detectedKeys[0] : null)
            }
            isConnected={isConnected}
            isVerifying={isVerifying}
            title="Hardware Encryption Key"
            description="Plug in your YubiKey to enable encryption."
          />

          {/* Folder picker */}
          <div
            className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors
              ${selectedFiles.length ? "border-green-500 bg-green-50 dark:bg-green-950/20" : "border-muted-foreground/25 hover:bg-muted/30"}
              ${uploadState === "uploading" ? "pointer-events-none opacity-60" : ""}
            `}
            onClick={() => folderInputRef.current?.click()}
          >
            <input
              ref={folderInputRef}
              type="file"
              className="hidden"
              // @ts-expect-error webkitdirectory is not in React's types
              webkitdirectory=""
              multiple
              onChange={handleFolderChange}
              disabled={uploadState === "uploading"}
            />
            {selectedFiles.length > 0 ? (
              <div className="space-y-1">
                <CheckCircle2 className="h-8 w-8 mx-auto text-green-500" />
                <p className="font-medium">{vaultName}</p>
                <p className="text-sm text-muted-foreground">
                  {selectedFiles.length} file{selectedFiles.length !== 1 ? "s" : ""} selected
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <FolderOpen className="h-8 w-8 mx-auto text-muted-foreground" />
                <p className="font-medium">Click to select a folder</p>
                <p className="text-sm text-muted-foreground">
                  All files inside will be encrypted and uploaded
                </p>
              </div>
            )}
          </div>

          {/* Vault name override */}
          {selectedFiles.length > 0 && uploadState === "idle" && (
            <div className="space-y-1.5">
              <Label htmlFor="folder-vault-name">Vault name</Label>
              <Input
                id="folder-vault-name"
                value={vaultName}
                onChange={(e) => setVaultName(e.target.value)}
                placeholder="Vault name"
              />
            </div>
          )}

          {/* Progress */}
          {uploadState === "uploading" && (
            <div className="space-y-1">
              <Progress value={progress} className="h-2" />
              <p className="text-sm text-center text-muted-foreground animate-pulse">
                Encrypting and uploading… {progress}%
              </p>
            </div>
          )}

          {uploadState === "done" && (
            <div className="flex items-center gap-2 text-green-600 justify-center font-medium text-sm">
              <CheckCircle2 className="h-5 w-5" />
              All files uploaded successfully!
            </div>
          )}

          {uploadState === "error" && (
            <div className="flex items-center gap-2 text-red-600 justify-center text-sm bg-red-50 dark:bg-red-950/30 p-2 rounded">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {errorMessage}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={handleClose}
            disabled={uploadState === "uploading"}
          >
            Cancel
          </Button>
          <Button
            onClick={handleUpload}
            disabled={
              !selectedFiles.length ||
              !matchedKey?.id ||
              !vaultName.trim() ||
              uploadState === "uploading" ||
              uploadState === "done"
            }
          >
            {uploadState === "uploading" ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Uploading…
              </>
            ) : (
              <>
                <FolderKey className="h-4 w-4 mr-2" />
                Encrypt & Upload
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
