"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Button } from "@/components/ui/button";
import { Download, Trash2, FileText, FileImage, FileArchive, File, Key } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export interface EncryptedFile {
  id: number;
  original_filename: string;
  file_size: number;
  mime_type: string | null;
  created_at: string;
  security_key_id: number;
  security_key_serial: number | null;
  security_key_device: string | null;
}

interface ColumnOptions {
  onDownload: (file: EncryptedFile) => void;
  onDelete: (file: EncryptedFile) => void;
}

const getFileIcon = (mimeType: string | null) => {
  if (!mimeType) return <File className="h-4 w-4" />;
  
  if (mimeType.startsWith("image/")) {
    return <FileImage className="h-4 w-4 text-blue-500" />;
  } else if (mimeType.includes("pdf") || mimeType.includes("document") || mimeType.includes("text")) {
    return <FileText className="h-4 w-4 text-red-500" />;
  } else if (mimeType.includes("zip") || mimeType.includes("archive") || mimeType.includes("compressed")) {
    return <FileArchive className="h-4 w-4 text-yellow-500" />;
  }
  
  return <File className="h-4 w-4 text-gray-500" />;
};

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
};

const formatDate = (dateString: string): string => {
  const date = new Date(dateString);
  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export function secureFilesColumns(options: ColumnOptions): ColumnDef<EncryptedFile>[] {
  return [
    {
      accessorKey: "original_filename",
      header: "Filename",
      cell: ({ row }) => {
        const file = row.original;
        return (
          <div className="flex items-center gap-2">
            {getFileIcon(file.mime_type)}
            <span className="font-medium truncate max-w-[200px]" title={file.original_filename}>
              {file.original_filename}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: "file_size",
      header: "Size",
      cell: ({ row }) => {
        return <span className="text-sm text-muted-foreground">{formatFileSize(row.original.file_size)}</span>;
      },
    },
    {
      accessorKey: "mime_type",
      header: "Type",
      cell: ({ row }) => {
        const mimeType = row.original.mime_type;
        return (
          <Badge variant="outline" className="text-xs">
            {mimeType ? mimeType.split("/")[1]?.toUpperCase() || mimeType : "Unknown"}
          </Badge>
        );
      },
    },
    {
      accessorKey: "security_key_id",
      header: "Encrypted With",
      cell: ({ row }) => {
        const file = row.original;
        return (
          <div className="flex items-center gap-1">
            <Key className="h-3 w-3 text-green-500" />
            <span className="text-sm">
              {file.security_key_device || "Key"}{" "}
              {file.security_key_serial ? `#${file.security_key_serial}` : `#${file.security_key_id}`}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: "Uploaded",
      cell: ({ row }) => {
        return <span className="text-sm text-muted-foreground">{formatDate(row.original.created_at)}</span>;
      },
    },
    {
      id: "actions",
      header: "Actions",
      cell: ({ row }) => {
        const file = row.original;
        return (
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => options.onDownload(file)}
              title="Download & Decrypt"
            >
              <Download className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-red-500 hover:text-red-700 hover:bg-red-50"
              onClick={() => options.onDelete(file)}
              title="Delete file"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        );
      },
    },
  ];
}
