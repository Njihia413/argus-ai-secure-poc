"use client"

import * as React from "react"
import { ChevronLeft, ChevronRight } from "lucide-react"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import type {
  ColumnDef,
  ColumnFiltersState,
  SortingState,
  VisibilityState,
  RowSelectionState,
  TableOptions,
  Table as TableType,
  RowModel,
  Row,
  OnChangeFn,
  Updater,
  TableState,
} from "@tanstack/react-table"
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  getFacetedRowModel,
  getFacetedUniqueValues,
} from "@tanstack/react-table"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"

interface DataTableState {
  sorting?: SortingState
  columnFilters?: ColumnFiltersState
  columnVisibility?: VisibilityState
  rowSelection?: RowSelectionState
  globalFilter?: string
  columnOrder?: string[]
  columnPinning?: { left?: string[], right?: string[] }
  rowPinning?: { top?: string[], bottom?: string[] }
  expanded?: { [key: string]: boolean }
  grouping?: string[]
  columnSizing?: { [key: string]: number }
  columnSizingInfo?: { startOffset: number | null, startSize: number | null }
}

interface DataTableProps<TData> {
  columns: ColumnDef<TData>[]
  data: TData[]
  pageCount?: number // Add pageCount for server-side pagination
  onTableInit?: (table: TableType<TData>) => void
  meta?: Record<string, any>
  toolbar?: ((table: TableType<TData>) => React.ReactNode) | React.ReactNode
  state?: DataTableState & {
    pagination?: {
      pageIndex: number
      pageSize: number
    }
  }
  onSortingChange?: OnChangeFn<SortingState>
  onColumnFiltersChange?: OnChangeFn<ColumnFiltersState>
  onColumnVisibilityChange?: OnChangeFn<VisibilityState>
  onRowSelectionChange?: OnChangeFn<RowSelectionState>
  onPaginationChange?: OnChangeFn<{ pageIndex: number; pageSize: number }>
  enableRowSelection?: boolean
  getSortedRowModel?: boolean
  getFilteredRowModel?: boolean
  getPaginationRowModel?: boolean
}

const defaultState: DataTableState = {
  sorting: [],
  columnFilters: [],
  columnVisibility: {},
  rowSelection: {},
  globalFilter: "",
  columnOrder: [],
  columnPinning: { left: [], right: [] },
  rowPinning: { top: [], bottom: [] },
  expanded: {},
  grouping: [],
  columnSizing: {},
  columnSizingInfo: { startOffset: null, startSize: null }
}

export function DataTable<TData>({
  columns,
  data,
  pageCount, // Destructure pageCount
  onTableInit,
  meta,
  toolbar,
  state = defaultState,
  onSortingChange,
  onColumnFiltersChange,
  onColumnVisibilityChange,
  onRowSelectionChange,
  onPaginationChange,
  enableRowSelection = false,
  getSortedRowModel: enableSorting = false,
  getFilteredRowModel: enableFiltering = false,
}: DataTableProps<TData>) {
  const isManualPagination = onPaginationChange !== undefined && pageCount !== undefined;

  const [localState, setLocalState] = React.useState<DataTableState>(state)
  const [pagination, setPagination] = React.useState({
    pageIndex: 0,
    pageSize: 10,
  });

  const table = useReactTable<TData>({
    data,
    columns,
    pageCount: isManualPagination ? pageCount : Math.ceil(data.length / 10),
    state: {
      sorting: localState.sorting,
      columnFilters: localState.columnFilters,
      columnVisibility: localState.columnVisibility,
      rowSelection: localState.rowSelection,
      globalFilter: localState.globalFilter,
      pagination: isManualPagination ? state.pagination : pagination,
    },
    enableRowSelection,
    manualPagination: isManualPagination,
    getCoreRowModel: getCoreRowModel(),
    ...(!isManualPagination && { getPaginationRowModel: getPaginationRowModel() }),
    ...(enableSorting ? { getSortedRowModel: getSortedRowModel() } : {}),
    ...(enableFiltering ? { getFilteredRowModel: getFilteredRowModel() } : {}),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    onSortingChange: (updater) => {
      const value = typeof updater === 'function' ? updater(localState.sorting ?? []) : updater
      setLocalState((prev) => ({ ...prev, sorting: value }))
      onSortingChange?.(value)
    },
    onColumnFiltersChange: (updater) => {
      const value = typeof updater === 'function' ? updater(localState.columnFilters ?? []) : updater
      setLocalState((prev) => ({ ...prev, columnFilters: value }))
      onColumnFiltersChange?.(value)
    },
    onColumnVisibilityChange: (updater) => {
      const value = typeof updater === 'function' ? updater(localState.columnVisibility ?? {}) : updater
      setLocalState((prev) => ({ ...prev, columnVisibility: value }))
      onColumnVisibilityChange?.(value)
    },
    onRowSelectionChange: (updater) => {
      const value = typeof updater === 'function' ? updater(localState.rowSelection ?? {}) : updater
      setLocalState((prev) => ({ ...prev, rowSelection: value }))
      onRowSelectionChange?.(value)
    },
    onGlobalFilterChange: (value) => {
      setLocalState((prev) => ({ ...prev, globalFilter: value }))
    },
    onPaginationChange: isManualPagination ? onPaginationChange : setPagination,
    meta,
  })

  React.useEffect(() => {
    if (onTableInit) {
      onTableInit(table)
    }
  }, [table, onTableInit])

  return (
    <div>
      {toolbar && (
        <div className="flex items-center py-4">
          {typeof toolbar === 'function' ? toolbar(table) : toolbar}
        </div>
      )}
      <div className="rounded-md border border-solid border-[var(--card-border-themed)]">
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
                  className="hover:bg-muted/50"
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-3">
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
      <div className="flex items-center justify-between space-x-2 py-4">
        <div className="text-sm text-muted-foreground">
          {table.getFilteredSelectedRowModel().rows.length} of{" "}
          {table.getFilteredRowModel().rows.length} row(s) selected.
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center space-x-2">
            <Select
              value={`${table.getState().pagination?.pageSize || 10}`}
              onValueChange={(value) => {
                const newSize = Number(value);
                table.setPageSize(newSize);
                if (onPaginationChange) {
                  onPaginationChange({
                    pageSize: newSize,
                    pageIndex: 0,
                  });
                }
              }}
            >
              <SelectTrigger className="h-8 w-[70px] dark:bg-input bg-transparent border border-[var(--border)] rounded-3xl text-foreground hover:bg-transparent">
                <SelectValue placeholder={table.getState().pagination?.pageSize || 10} />
              </SelectTrigger>
              <SelectContent side="top">
                {[5, 10, 20, 30, 40, 50, 100].map((pageSize) => (
                  <SelectItem key={pageSize} value={`${pageSize}`}>
                    {pageSize}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">Rows per page</p>
            <div className="flex w-[100px] items-center justify-center text-sm text-muted-foreground">
              Page {table.getState().pagination.pageIndex + 1} of{" "}
              {table.getPageCount()}
            </div>
            <div className="flex items-center space-x-1">
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8 p-0 border border-[var(--border)] dark:bg-input bg-transparent hover:bg-transparent"
                onClick={() => {
                  table.previousPage();
                  if (onPaginationChange) {
                    const currentState = table.getState().pagination;
                    onPaginationChange({
                      pageSize: currentState.pageSize,
                      pageIndex: currentState.pageIndex - 1,
                    });
                  }
                }}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronLeft className="h-4 w-4" />
                <span className="sr-only">Previous page</span>
              </Button>
              <Button
                variant="outline"
                size="icon"
                className="h-8 w-8 p-0 border border-[var(--border)] dark:bg-input bg-transparent hover:bg-transparent"
                onClick={() => {
                  table.nextPage();
                  if (onPaginationChange) {
                    const currentState = table.getState().pagination;
                    onPaginationChange({
                      pageSize: currentState.pageSize,
                      pageIndex: currentState.pageIndex + 1,
                    });
                  }
                }}
                disabled={!table.getCanNextPage()}
              >
                <ChevronRight className="h-4 w-4" />
                <span className="sr-only">Next page</span>
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
