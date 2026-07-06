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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { FolderKey, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { API_URL } from "@/app/utils/constants";
import { Vault } from "./vault-card";

interface CreateVaultDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (vault: Vault) => void;
  /** Pre-fill name (used by upload-folder-dialog) */
  initialName?: string;
  /** Admin: create vault on behalf of this user */
  userId?: number | null;
}

export function CreateVaultDialog({
  open,
  onOpenChange,
  onCreated,
  initialName = "",
  userId,
}: CreateVaultDialogProps) {
  const { user } = useAuthStore();
  const authToken = user?.authToken ?? null;
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Sync initialName when dialog opens
  const handleOpenChange = (val: boolean) => {
    if (val) {
      setName(initialName);
      setDescription("");
    }
    onOpenChange(val);
  };

  const handleCreate = async () => {
    const trimmed = name.trim();
    if (!trimmed) {
      toast.error("Vault name is required");
      return;
    }

    if (!authToken) return;

    setIsSubmitting(true);
    try {
      const response = await fetch(`${API_URL}/vaults`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${authToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: trimmed,
          description: description.trim(),
          ...(userId != null && { owner_user_id: userId }),
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error || "Failed to create vault");
      }

      const data = await response.json();
      toast.success(`Vault "${trimmed}" created`);
      onCreated(data.vault);
      onOpenChange(false);
      setName("");
      setDescription("");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to create vault");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-[420px] font-montserrat">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderKey className="h-5 w-5 text-primary" />
            Create Vault
          </DialogTitle>
          <DialogDescription>
            A vault groups encrypted files together. Files inside share the same
            access controls.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="vault-name">Name</Label>
            <Input
              id="vault-name"
              placeholder="e.g. HR Documents"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vault-desc">Description (optional)</Label>
            <Textarea
              id="vault-desc"
              placeholder="What's stored in this vault?"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              className="resize-none"
            />
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button onClick={handleCreate} disabled={isSubmitting || !name.trim()}>
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Creating…
              </>
            ) : (
              "Create Vault"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
