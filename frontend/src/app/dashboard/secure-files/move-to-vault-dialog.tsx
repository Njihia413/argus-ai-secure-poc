"use client";

import { useState } from "react";
import { useAuthStore } from "@/store/auth";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { FolderInput, FolderKey, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { API_URL } from "@/app/utils/constants";
import { EncryptedFile } from "./secure-files-columns";
import { Vault } from "./vault-card";

interface MoveToVaultDialogProps {
  file: EncryptedFile | null;
  vaults: Vault[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onMoved: () => void;
}

export function MoveToVaultDialog({
  file,
  vaults,
  open,
  onOpenChange,
  onMoved,
}: MoveToVaultDialogProps) {
  const { user } = useAuthStore();
  const authToken = user?.authToken ?? null;
  const [selectedVaultId, setSelectedVaultId] = useState<number | null | undefined>(
    undefined
  );
  const [isMoving, setIsMoving] = useState(false);

  const handleMove = async () => {
    if (!file || selectedVaultId === undefined) return;
    if (!authToken) return;

    setIsMoving(true);
    try {
      const res = await fetch(`${API_URL}/files/${file.id}/vault`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ vault_id: selectedVaultId }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to move file");
      }

      const target = vaults.find((v) => v.id === selectedVaultId);
      toast.success(
        selectedVaultId === null
          ? `"${file.original_filename}" removed from vault`
          : `"${file.original_filename}" moved to ${target?.name}`
      );
      onMoved();
      onOpenChange(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to move file");
    } finally {
      setIsMoving(false);
      setSelectedVaultId(undefined);
    }
  };

  const handleClose = () => {
    setSelectedVaultId(undefined);
    onOpenChange(false);
  };

  const availableVaults = vaults.filter((v) => v.id !== file?.vault_id);
  const canUngroup = file?.vault_id != null;

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[420px] font-montserrat">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderInput className="h-5 w-5 text-primary" />
            Move to Vault
          </DialogTitle>
          <DialogDescription>
            Choose a vault for{" "}
            <span className="font-medium text-foreground">
              {file?.original_filename}
            </span>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2 py-2 max-h-64 overflow-y-auto">
          {availableVaults.length === 0 && !canUngroup && (
            <p className="text-sm text-muted-foreground text-center py-4">
              No other vaults available. Create a vault first.
            </p>
          )}

          {availableVaults.map((vault) => (
            <button
              key={vault.id}
              onClick={() => setSelectedVaultId(vault.id)}
              className={`w-full flex items-center gap-3 p-3 rounded-lg border text-left transition-colors
                ${selectedVaultId === vault.id
                  ? "border-primary bg-primary/5"
                  : "border-border hover:bg-muted/50"
                }`}
            >
              <FolderKey className="h-5 w-5 text-primary shrink-0" />
              <div className="min-w-0">
                <p className="font-medium text-sm truncate">{vault.name}</p>
                <p className="text-xs text-muted-foreground">
                  {vault.file_count} file{vault.file_count !== 1 ? "s" : ""}
                </p>
              </div>
            </button>
          ))}

          {canUngroup && (
            <button
              onClick={() => setSelectedVaultId(null)}
              className={`w-full flex items-center gap-3 p-3 rounded-lg border text-left transition-colors
                ${selectedVaultId === null
                  ? "border-destructive bg-destructive/5"
                  : "border-border hover:bg-muted/50"
                }`}
            >
              <X className="h-5 w-5 text-muted-foreground shrink-0" />
              <div>
                <p className="font-medium text-sm">Remove from vault</p>
                <p className="text-xs text-muted-foreground">File becomes ungrouped</p>
              </div>
            </button>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={isMoving}>
            Cancel
          </Button>
          <Button
            onClick={handleMove}
            disabled={selectedVaultId === undefined || isMoving}
          >
            {isMoving ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Moving…
              </>
            ) : (
              "Move"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
