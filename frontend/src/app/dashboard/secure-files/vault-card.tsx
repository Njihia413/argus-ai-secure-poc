"use client";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { FolderKey, MoreHorizontal, Pencil, Trash2 } from "lucide-react";

export interface Vault {
  id: number;
  name: string;
  description: string | null;
  owner_user_id: number;
  file_count: number;
  total_size: number;
  created_at: string;
  updated_at: string | null;
}

interface VaultCardProps {
  vault: Vault;
  onClick: (vault: Vault) => void;
  onRename: (vault: Vault) => void;
  onDelete: (vault: Vault) => void;
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function VaultCard({ vault, onClick, onRename, onDelete }: VaultCardProps) {
  return (
    <Card
      className="cursor-pointer hover:border-primary/50 transition-all group bg-gradient-to-t from-[var(--overview-card-gradient-from)] to-[var(--overview-card-gradient-to)] hover:shadow-md"
      onClick={() => onClick(vault)}
    >
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="h-9 w-9 rounded-xl bg-primary/10 flex items-center justify-center shrink-0 group-hover:bg-primary/15 transition-colors">
            <FolderKey className="h-4.5 w-4.5 text-primary" />
          </div>
          <span className="font-semibold truncate text-sm leading-tight">{vault.name}</span>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
            <DropdownMenuItem onClick={() => onRename(vault)}>
              <Pencil className="h-4 w-4 mr-2" />
              Rename
            </DropdownMenuItem>
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => onDelete(vault)}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </CardHeader>
      <CardContent className="pt-0">
        {vault.description && (
          <p className="text-xs text-muted-foreground mb-3 line-clamp-2">
            {vault.description}
          </p>
        )}
        <p className="text-2xl font-bold tracking-tight">{vault.file_count}</p>
        <p className="text-xs text-muted-foreground mt-0.5">
          {vault.file_count === 1 ? "file" : "files"} · {formatFileSize(vault.total_size)}
        </p>
      </CardContent>
    </Card>
  );
}
