"use client";

import { useState, useCallback, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Upload, FileKey, X, CheckCircle2, AlertCircle, Shield, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { API_URL } from "@/app/utils/constants";
import { useYubiKeyDetection } from "@/app/hooks/use-yubikey-detection";
import { KeyDetectionOverlay } from "@/components/secure-files/key-detection-overlay";

interface SecurityKey {
  id: number;
  serial_number: number | null;
  device_type: string | null;
  form_factor: string | null;
}

interface FileUploadDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  securityKeys: SecurityKey[]; // Still used as a fallback or reference if needed
  onUploadComplete: () => void;
  userId?: number | null;
}

type UploadStatus = "idle" | "uploading" | "success" | "error";

export function FileUploadDialog({
  open,
  onOpenChange,
  onUploadComplete, // Corrected prop usage
  userId,
}: FileUploadDialogProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>("idle");
  const [errorMessage, setErrorMessage] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);

  const { detectedKeys, isConnected, isVerifying } = useYubiKeyDetection(open);
  
  // Find a detected key that is also registered to the user
  const matchedKey = detectedKeys.find(k => k.id !== undefined);

  const handleFileSelect = useCallback((file: File) => {
    setSelectedFile(file);
    setUploadStatus("idle");
    setErrorMessage("");
    setUploadProgress(0);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragOver(false);
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        handleFileSelect(files[0]);
      }
    },
    [handleFileSelect]
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleFileInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        handleFileSelect(files[0]);
      }
    },
    [handleFileSelect]
  );

  const handleUpload = async () => {
    const userInfo = JSON.parse(sessionStorage.getItem("user") || "{}");
    const authToken = userInfo.authToken;
    if (!selectedFile || !matchedKey?.id || !authToken) return;

    setUploadStatus("uploading");
    setUploadProgress(0);
    setErrorMessage("");

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("security_key_id", matchedKey.id.toString());
      if (userId) {
        formData.append("user_id", userId.toString());
      }

      // Simulate progress for better UX
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      const response = await fetch(`${API_URL}/files/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
        body: formData,
      });

      clearInterval(progressInterval);

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Upload failed");
      }

      setUploadProgress(100);
      setUploadStatus("success");
      toast.success("File encrypted and uploaded successfully");
      
      // Wait a moment before closing
      setTimeout(() => {
        resetState();
        onUploadComplete();
      }, 1500);
    } catch (error) {
      console.error("Upload error:", error);
      setUploadStatus("error");
      setErrorMessage(error instanceof Error ? error.message : "Upload failed");
      toast.error("Failed to upload file");
    }
  };

  const resetState = () => {
    setSelectedFile(null);
    setUploadProgress(0);
    setUploadStatus("idle");
    setErrorMessage("");
  };

  const handleClose = () => {
    if (uploadStatus !== "uploading") {
      resetState();
      onOpenChange(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[500px] font-montserrat">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-montserrat tracking-tight">
            <FileKey className="h-5 w-5 text-primary" />
            Upload File
          </DialogTitle>
          <DialogDescription className="font-montserrat">
            Your file will be encrypted before storage using your hardware security key.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Automatic Key Detection */}
          <KeyDetectionOverlay 
            detectedKey={matchedKey || (detectedKeys.length > 0 ? detectedKeys[0] : null)}
            isConnected={isConnected}
            isVerifying={isVerifying}
            title="Hardware Encryption Key"
            description="Plug in your YubiKey to enable encryption."
          />

          {/* File Drop Zone */}
          <div
            className={`
              border-2 border-dashed rounded-lg p-8 text-center transition-all duration-200
              ${isDragOver ? "border-primary bg-primary/5 scale-102" : "border-muted-foreground/25"}
              ${selectedFile ? "border-green-500 bg-green-50 dark:bg-green-950/20" : ""}
              ${uploadStatus === "error" ? "border-red-500 bg-red-50 dark:bg-red-950/20" : ""}
              ${uploadStatus === "uploading" ? "pointer-events-none opacity-60" : "cursor-pointer hover:bg-muted/30"}
            `}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => document.getElementById("file-input")?.click()}
          >
            <input
              id="file-input"
              type="file"
              className="hidden"
              onChange={handleFileInputChange}
              disabled={uploadStatus === "uploading"}
            />
            
            {selectedFile ? (
              <div className="space-y-2">
                <CheckCircle2 className="h-10 w-10 mx-auto text-green-500" />
                <p className="font-medium font-montserrat">{selectedFile.name}</p>
                <p className="text-sm text-muted-foreground font-montserrat">
                  {formatFileSize(selectedFile.size)}
                </p>
                {uploadStatus !== "uploading" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="font-montserrat h-8"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      setUploadStatus("idle");
                    }}
                  >
                    <X className="h-4 w-4 mr-1" />
                    Remove
                  </Button>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                <Upload className="h-10 w-10 mx-auto text-muted-foreground" />
                <p className="font-medium font-montserrat">Drop your file here</p>
                <p className="text-sm text-muted-foreground font-montserrat">
                  or click to browse
                </p>
              </div>
            )}
          </div>

          {/* Upload Progress */}
          {uploadStatus === "uploading" && (
            <div className="space-y-2">
              <Progress value={uploadProgress} className="h-2" />
              <p className="text-sm text-center text-muted-foreground font-montserrat animate-pulse">
                Encrypting and uploading... {uploadProgress}%
              </p>
            </div>
          )}

          {/* Success Message */}
          {uploadStatus === "success" && (
            <div className="flex items-center gap-2 text-green-600 justify-center font-montserrat font-medium">
              <CheckCircle2 className="h-5 w-5" />
              <span>File encrypted and uploaded successfully!</span>
            </div>
          )}

          {/* Error Message */}
          {uploadStatus === "error" && (
            <div className="flex items-center gap-2 text-red-600 justify-center font-montserrat text-sm bg-red-50 dark:bg-red-950/30 p-2 rounded">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t pt-4">
          <Button
            variant="outline"
            className="font-montserrat"
            onClick={handleClose}
            disabled={uploadStatus === "uploading"}
          >
            Cancel
          </Button>
          <Button
            className="font-montserrat"
            onClick={handleUpload}
            disabled={!selectedFile || !matchedKey?.id || uploadStatus === "uploading" || uploadStatus === "success"}
          >
            {uploadStatus === "uploading" ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Encrypting...
              </>
            ) : (
              <>
                <Shield className="h-4 w-4 mr-2" />
                Encrypt & Upload
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

