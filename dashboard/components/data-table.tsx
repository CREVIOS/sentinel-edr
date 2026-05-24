"use client";

import * as React from "react";
import { motion } from "motion/react";
import {
  type ColumnDef,
  type SortingState,
  type VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ArrowDown, ArrowUp, ChevronsUpDown, Columns3, Eye } from "lucide-react";
import { cn } from "@/lib/utils";

/** Sortable column header — drop into a column's `header`. Renders a sort affordance. */
export function SortHeader<T>({ column, title }: { column: import("@tanstack/react-table").Column<T, unknown>; title: string }) {
  if (!column.getCanSort()) {
    return <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em]">{title}</span>;
  }
  const dir = column.getIsSorted();
  return (
    <button
      onClick={() => column.toggleSorting(dir === "asc")}
      className="-ml-1 inline-flex items-center gap-1 rounded px-1 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] transition-colors hover:text-foreground"
    >
      {title}
      {dir === "asc" ? <ArrowUp className="size-3" /> : dir === "desc" ? <ArrowDown className="size-3" /> : <ChevronsUpDown className="size-3 opacity-40" />}
    </button>
  );
}

interface DataTableProps<T> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: ColumnDef<T, any>[];
  data: T[];
  onRowClick?: (row: T) => void;
  /** show a global filter input with this placeholder */
  filterPlaceholder?: string;
  /** enable client pagination at this page size; omit to render all rows */
  pageSize?: number;
  /** extra toolbar controls rendered to the left of search/columns */
  toolbar?: React.ReactNode;
  initialSort?: SortingState;
  empty?: React.ReactNode;
  /** stable row id (so Motion only animates genuinely new rows, e.g. live tail) */
  rowId?: (row: T) => string;
}

export function DataTable<T>({
  columns, data, onRowClick, filterPlaceholder, pageSize, toolbar, initialSort, empty, rowId,
}: DataTableProps<T>) {
  const [sorting, setSorting] = React.useState<SortingState>(initialSort ?? []);
  const [globalFilter, setGlobalFilter] = React.useState("");
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({});

  const table = useReactTable<T>({
    data,
    columns,
    state: { sorting, globalFilter, columnVisibility },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    ...(pageSize ? { getPaginationRowModel: getPaginationRowModel() } : {}),
    ...(rowId ? { getRowId: (r) => rowId(r) } : {}),
    initialState: pageSize ? { pagination: { pageSize } } : {},
  });

  const rows = table.getRowModel().rows;
  const hideable = table.getAllColumns().filter((c) => c.getCanHide());

  return (
    <div className="space-y-3">
      {(filterPlaceholder || toolbar || hideable.length > 0) && (
        <div className="flex flex-wrap items-center gap-2">
          {toolbar}
          {filterPlaceholder && (
            <Input
              value={globalFilter}
              onChange={(e) => setGlobalFilter(e.target.value)}
              placeholder={filterPlaceholder}
              className="h-8 max-w-xs"
            />
          )}
          {hideable.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" className="ml-auto gap-1.5">
                  <Eye className="size-3.5" /> Columns <Columns3 className="size-3.5 opacity-60" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Visible columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {hideable.map((col) => (
                  <DropdownMenuCheckboxItem
                    key={col.id}
                    checked={col.getIsVisible()}
                    onCheckedChange={(v) => col.toggleVisibility(!!v)}
                    className="capitalize"
                  >
                    {col.id}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => (
                  <TableHead key={h.id} style={{ width: h.getSize() !== 150 ? h.getSize() : undefined }}>
                    {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <tbody data-slot="table-body" className="[&_tr:last-child]:border-0">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="py-14 text-center font-mono text-sm text-muted-foreground">
                  {empty ?? "no records"}
                </td>
              </tr>
            ) : (
              rows.map((row) => (
                <motion.tr
                  key={row.id}
                  initial={{ opacity: 0, y: -5 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                  onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                  data-slot="table-row"
                  className={cn(
                    "border-b border-l-2 border-l-transparent transition-colors hover:border-l-primary hover:bg-primary/[0.04]",
                    onRowClick && "group cursor-pointer",
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </motion.tr>
              ))
            )}
          </tbody>
        </Table>
      </div>

      {pageSize && rows.length > 0 && (
        <div className="flex items-center justify-between px-1">
          <span className="font-mono text-xs text-muted-foreground">
            {table.getFilteredRowModel().rows.length} rows · page {table.getState().pagination.pageIndex + 1}/{table.getPageCount()}
          </span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</Button>
            <Button variant="outline" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
