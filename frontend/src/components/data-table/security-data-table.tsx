"use client"

import * as React from "react"
import { SecurityKey, SecurityKeyTableMeta } from "./security-key-columns"
import {
    ColumnDef,
    ColumnFiltersState,
    SortingState,
    flexRender,
    getCoreRowModel,
    getFilteredRowModel,
    getPaginationRowModel,
    getSortedRowModel,
    useReactTable,
    getFacetedRowModel,
    getFacetedUniqueValues,
} from "@tanstack/react-table"
import { Checkbox } from "@/components/ui/checkbox"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"

interface DataTableProps<TData extends SecurityKey, TValue> {
    columns: ColumnDef<TData, TValue>[]
    data: TData[]
    onTableInit?: (table: any) => void
    meta?: SecurityKeyTableMeta
    enableRowSelection?: boolean
    onRowSelectionChange?: (value: any) => void
}

export function SecurityDataTable<TData extends SecurityKey, TValue>({
                                                                         columns,
                                                                         data,
                                                                         onTableInit,
                                                                         meta,
                                                                         enableRowSelection = false,
                                                                         onRowSelectionChange
                                                                     }: DataTableProps<TData, TValue>) {
    const [sorting, setSorting] = React.useState<SortingState>([])
    const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
    const [globalFilter, setGlobalFilter] = React.useState('')
    const [rowSelection, setRowSelection] = React.useState({})

    const selectionColumn: ColumnDef<TData, any> = {
        id: "select",
        header: ({ table }) => (
            <Checkbox
                checked={table.getIsAllPageRowsSelected()}
                onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
                aria-label="Select all"
                className="translate-y-[2px]"
            />
        ),
        cell: ({ row }) => (
            <Checkbox
                checked={row.getIsSelected()}
                onCheckedChange={(value) => row.toggleSelected(!!value)}
                aria-label="Select row"
                className="translate-y-[2px]"
            />
        ),
        enableSorting: false,
        enableHiding: false,
    }

    const allColumns = [selectionColumn, ...columns]

    const table = useReactTable({
        data,
        columns: enableRowSelection ? allColumns : columns,
        getCoreRowModel: getCoreRowModel(),
        getPaginationRowModel: getPaginationRowModel(),
        onSortingChange: setSorting,
        getSortedRowModel: getSortedRowModel(),
        onColumnFiltersChange: setColumnFilters,
        getFilteredRowModel: getFilteredRowModel(),
        getFacetedRowModel: getFacetedRowModel(),
        getFacetedUniqueValues: getFacetedUniqueValues(),
        onGlobalFilterChange: setGlobalFilter,
        enableRowSelection,
        onRowSelectionChange: (updater) => {
            const value = typeof updater === 'function' ? updater(rowSelection) : updater
            setRowSelection(value)
            onRowSelectionChange?.(value)
        },
        state: {
            sorting,
            columnFilters,
            globalFilter,
            rowSelection,
        },
        meta: meta || {},
    })

    React.useEffect(() => {
        if (onTableInit) {
            onTableInit(table)
        }
    }, [table, onTableInit])

    return (
        <div>
            <div className="rounded-md border border-zinc-200 dark:border-zinc-800">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => {
                                    return (
                                        <TableHead key={header.id}>
                                            {header.isPlaceholder
                                                ? null
                                                : flexRender(
                                                    header.column.columnDef.header,
                                                    header.getContext()
                                                )}
                                        </TableHead>
                                    )
                                })}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows?.length ? (
                            table.getRowModel().rows.map((row) => (
                                <TableRow
                                    key={row.id}
                                    data-state={row.getIsSelected() && "selected"}
                                >
                                    {row.getVisibleCells().map((cell) => (
                                        <TableCell key={cell.id} className="p-4">
                                            {flexRender(
                                                cell.column.columnDef.cell,
                                                cell.getContext()
                                            )}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell
                                    colSpan={columns.length}
                                    className="h-24 text-center"
                                >
                                    No results.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>
        </div>
    )
}
