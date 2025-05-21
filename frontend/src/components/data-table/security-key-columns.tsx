"use client"

import { ColumnDef, TableMeta } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MoreHorizontal, Edit, Power, Trash, RefreshCw, Key } from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export interface SecurityKey {
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

export interface SecurityKeyTableMeta extends TableMeta<SecurityKey> {
  setSelectedKey: (key: SecurityKey | null) => void
  setShowKeyDetailsModal: (show: boolean) => void
  setKeyDetails: (details: { model: string; type: string; serialNumber: string; pin: string }) => void
  setShowDeactivateDialog: (show: boolean) => void
  setShowDeleteConfirm: (show: boolean) => void
  handleResetKey: (keyId: number) => Promise<void>
  setIsKeyReassigned?: (value: boolean) => void
  setShowRegistrationModal?: (show: boolean) => void
}

export const securityKeyColumns: ColumnDef<SecurityKey, unknown>[] = [
  {
    accessorKey: "model",
    header: "Model",
    cell: ({ row }) => {
      return row.getValue("model") || "N/A"
    }
  },
  {
    accessorKey: "type",
    header: "Type",
    cell: ({ row }) => {
      return row.getValue("type") || "N/A"
    }
  },
  {
    accessorKey: "serialNumber",
    header: "Serial Number",
    cell: ({ row }) => {
      return row.getValue("serialNumber") || "N/A"
    }
  },
  {
    accessorKey: "isActive",
    header: "Status",
    cell: ({ row }) => {
      const isActive = row.getValue("isActive")

      return isActive ? (
        <Badge variant="outline" className="text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
          Active
        </Badge>
      ) : (
        <Badge variant="outline" className="text-red-700 dark:text-red-400 border-red-300 dark:border-red-700">
          Inactive
        </Badge>
      )
    }
  },
  {
    accessorKey: "createdAt",
    header: "Registered On",
    cell: ({ row }) => {
      return new Date(row.getValue("createdAt")).toLocaleString('en-US', {
        dateStyle: 'medium',
        timeStyle: 'short'
      })
    }
  },
  {
    accessorKey: "lastUsed",
    header: "Last Used",
    cell: ({ row }) => {
      const lastUsed = row.getValue("lastUsed")
      return lastUsed ? (
        new Date(lastUsed as string).toLocaleString('en-US', {
          dateStyle: 'medium',
          timeStyle: 'short'
        })
      ) : (
        "Never used"
      )
    }
  },
  {
    id: "actions",
    header: "Actions",
    cell: ({ row, table }) => {
      const key = row.original

      return (
        <div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="h-8 w-8 p-0">
                <MoreHorizontal className="h-4 w-4"/>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
             <DropdownMenuItem
               onClick={() => {
                 if (!table.options.meta) return
                 const meta = table.options.meta as SecurityKeyTableMeta
                 meta.setSelectedKey(key)
                 meta.setKeyDetails({
                   model: key.model || '',
                   type: key.type || '',
                   serialNumber: key.serialNumber || '',
                   pin: ''
                 })
                 meta.setShowKeyDetailsModal(true)
               }}
             >
               <Edit className="mr-2 h-4 w-4" />
               Edit Details
             </DropdownMenuItem>

             {!key.isActive && (
               <>
                 {/* Show Register Key option if key is reset or was never formally deactivated */}
                 {(key.deactivatedAt === null || key.credentialId === null) && (
                    <DropdownMenuItem
                        onClick={() => {
                        if (!table.options.meta) return
                        const meta = table.options.meta as SecurityKeyTableMeta
                        meta.setSelectedKey(key)
                        meta.setKeyDetails({
                            model: key.model || '',
                            type: key.type || '',
                            serialNumber: key.serialNumber || '',
                            pin: ''
                        })
                        meta.setIsKeyReassigned?.(true)
                        meta.setShowKeyDetailsModal(true)
                        }}
                        className="text-green-600"
                    >
                        <Key className="mr-2 h-4 w-4" />
                        Register Key
                    </DropdownMenuItem>
                 )}

                 {/* Show Reset Key option if key is deactivated AND has not been reset yet */}
                 {(key.deactivatedAt !== null && key.credentialId !== null) && (
                   <DropdownMenuItem
                     onClick={async () => {
                       if (!table.options.meta) return
                       const meta = table.options.meta as SecurityKeyTableMeta
                       meta.setSelectedKey(key)
                       await meta.handleResetKey(key.id)
                     }}
                     className="text-blue-600"
                   >
                     <RefreshCw className="mr-2 h-4 w-4" />
                     Reset Key
                   </DropdownMenuItem>
                 )}
               </>
             )}
             
            {key.isActive && (
              <DropdownMenuItem
                onClick={() => {
                  if (!table.options.meta) return
                  const meta = table.options.meta as SecurityKeyTableMeta
                  meta.setSelectedKey(key)
                  meta.setShowDeactivateDialog(true)
                }}
                className="text-yellow-600"
              >
                <Power className="mr-2 h-4 w-4" />
                Deactivate
              </DropdownMenuItem>
            )}

            <DropdownMenuItem
              onClick={() => {
                if (!table.options.meta) return
                const meta = table.options.meta as SecurityKeyTableMeta
                meta.setSelectedKey(key)
                meta.setShowDeleteConfirm(true)
              }}
              className="text-red-600"
            >
              <Trash className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
          </DropdownMenu>
        </div>
      )
    }
  }
]