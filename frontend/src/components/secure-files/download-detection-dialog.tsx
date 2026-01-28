"use client";

import { useEffect, useState } from "react";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { KeyDetectionOverlay } from "./key-detection-overlay";
import { useYubiKeyDetection } from "@/app/hooks/use-yubikey-detection";
import { EncryptedFile } from "@/app/dashboard/secure-files/secure-files-columns";
import { AlertCircle, Download, Loader2, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";

interface DownloadDetectionDialogProps {
  file: EncryptedFile | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDownloadReady: (file: EncryptedFile, keyId: number) => void;
}

export function DownloadDetectionDialog({
  file,
  open,
  onOpenChange,
  onDownloadReady,
}: DownloadDetectionDialogProps) {
  const { detectedKeys, isConnected, isVerifying } = useYubiKeyDetection(open);
  const [error, setError] = useState<string | null>(null);
  const [isDownloading, setIsDownloading] = useState(false);
  const [verifiedKeyId, setVerifiedKeyId] = useState<number | null>(null);

  useEffect(() => {
    if (!open) {
      setError(null);
      setIsDownloading(false);
      setVerifiedKeyId(null);
      return;
    }

    if (detectedKeys.length > 0 && file) {
      const key = detectedKeys[0];
      
      // 1. Check if the key belongs to the user
      if (key.id === undefined) {
        setError("This security key is not recognized for your account.");
        setVerifiedKeyId(null);
        return;
      }

      // 2. Check if it's the CORRECT key for this file
      if (key.id !== file.security_key_id) {
        setError("Incorrect security key. Please insert the specific hardware key used to encrypt this file.");
        setVerifiedKeyId(null);
        return;
      }

      // 3. Match! Enable download button
      setError(null);
      setVerifiedKeyId(key.id);
    } else {
      // Key was unplugged or not detected - reset verification state
      setError(null);
      setVerifiedKeyId(null);
    }
  }, [detectedKeys, file, open]);

  const handleManualDownload = () => {
    if (file && verifiedKeyId) {
      setIsDownloading(true);
      onDownloadReady(file, verifiedKeyId);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="font-montserrat">
        <AlertDialogHeader>
          <AlertDialogTitle className="font-montserrat">Security Key Required</AlertDialogTitle>
          <AlertDialogDescription className="font-montserrat">
            To decrypt and download <strong>{file?.original_filename}</strong>, please insert the security key used for its encryption.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="py-4">
          <KeyDetectionOverlay
            detectedKey={detectedKeys[0] || null}
            isConnected={isConnected}
            isVerifying={isVerifying}
            title="Download Authorization"
            description="Waiting for hardware key..."
          />
          
          {error && (
            <div className="mt-4 p-3 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 rounded-lg flex items-start gap-2 text-red-600 text-sm animate-in slide-in-from-top-2 duration-300">
              <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
              <span className="font-montserrat">{error}</span>
            </div>
          )}

          {verifiedKeyId && !isDownloading && (
            <div className="mt-4 flex items-center justify-center gap-2 text-green-600 font-medium font-montserrat animate-in zoom-in duration-300">
              <CheckCircle2 className="h-5 w-5" />
              Key Verified. Ready to download.
            </div>
          )}

          {isDownloading && (
            <div className="mt-4 flex items-center justify-center gap-2 text-primary font-medium font-montserrat animate-pulse">
              <Loader2 className="h-4 w-4 animate-spin" />
              Decrypting file...
            </div>
          )}
        </div>

        <AlertDialogFooter className="flex gap-2">
          <AlertDialogCancel className="font-montserrat" disabled={isDownloading}>
            Cancel
          </AlertDialogCancel>
          <Button
            className="font-montserrat"
            disabled={!verifiedKeyId || isDownloading}
            onClick={handleManualDownload}
          >
            {isDownloading ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Processing...
              </>
            ) : (
              <>
                <Download className="h-4 w-4 mr-2" />
                Download Now
              </>
            )}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

