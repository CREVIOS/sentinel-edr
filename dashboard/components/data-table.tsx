"use client";

import * as React from "react";
import { motion } from "motion/react";
import {
  type ColumnDef,
  type SortingState,
  type VisibilityState,
  type RowSelectionState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  Table, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ArrowDown, ArrowUp, ChevronsUpDown, Columns3, Rows3, Rows4, X } from "lucide-react";
import { cn } from "@/lib/utils";

/** Honor the operator's OS reduced-motion preference (reactive to changes). */
function usePrefersReducedMotion() {
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    const m = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(m.matches);
    const h = () => setReduced(m.matches);
    m.addEventListener("change", h);
    return () => m.removeEventListener("change", h);
  }, []);
  return reduced;
}

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

type Density = "comfortable" | "compact";

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
  /** show skeleton rows instead of the empty state during the initial fetch */
  loading?: boolean;
  /** stable row id (so Motion only animates genuinely new rows, e.g. live tail) */
  rowId?: (row: T) => string;
  /** persist sort / columns / density across reloads under this key (a saved view) */
  tableId?: string;
  /** opt-in multi-select with a checkbox column */
  enableSelection?: boolean;
  /** render a contextual bulk-action bar when rows are selected */
  bulkActions?: (selected: T[], clear: () => void) => React.ReactNode;
  /** show the compact/comfortable density toggle */
  enableDensity?: boolean;
}

export function DataTable<T>({
  columns, data, onRowClick, filterPlaceholder, pageSize, toolbar, initialSort, empty, loading, rowId,
  tableId, enableSelection, bulkActions, enableDensity = true,
}: DataTableProps<T>) {
  const [sorting, setSorting] = React.useState<SortingState>(initialSort ?? []);
  const [globalFilter, setGlobalFilter] = React.useState("");
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>({});
  const [rowSelection, setRowSelection] = React.useState<RowSelectionState>({});
  const [density, setDensity] = React.useState<Density>("comfortable");
  const reduceMotion = usePrefersReducedMotion();
  const restored = React.useRef(false);

  // Restore a persisted view (sort / columns / density) once, before first paint of data.
  React.useEffect(() => {
    if (!tableId || restored.current) return;
    restored.current = true;
    try {
      const raw = localStorage.getItem(`dt:${tableId}`);
      if (!raw) return;
      const v = JSON.parse(raw);
      if (Array.isArray(v.sorting)) setSorting(v.sorting);
      if (v.columnVisibility && typeof v.columnVisibility === "object") setColumnVisibility(v.columnVisibility);
      if (v.density === "compact" || v.density === "comfortable") setDensity(v.density);
    } catch { /* ignore corrupt view */ }
  }, [tableId]);

  React.useEffect(() => {
    if (!tableId || !restored.current) return;
    try { localStorage.setItem(`dt:${tableId}`, JSON.stringify({ sorting, columnVisibility, density })); } catch { /* quota */ }
  }, [tableId, sorting, columnVisibility, density]);

  // Prepend a selection column when enabled.
  const allColumns = React.useMemo<ColumnDef<T, unknown>[]>(() => {
    if (!enableSelection) return columns as ColumnDef<T, unknown>[];
    const selectCol: ColumnDef<T, unknown> = {
      id: "__select",
      enableHiding: false,
      enableSorting: false,
      size: 36,
      header: ({ table }) => (
        <Checkbox
          aria-label="Select all rows"
          checked={table.getIsAllPageRowsSelected() || (table.getIsSomePageRowsSelected() && "indeterminate")}
          onCheckedChange={(v) => table.toggleAllPageRowsSelected(!!v)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          aria-label="Select row"
          checked={row.getIsSelected()}
          onCheckedChange={(v) => row.toggleSelected(!!v)}
          onClick={(e) => e.stopPropagation()}
        />
      ),
    };
    return [selectCol, ...(columns as ColumnDef<T, unknown>[])];
  }, [columns, enableSelection]);

  const table = useReactTable<T>({
    data,
    columns: allColumns,
    state: { sorting, globalFilter, columnVisibility, rowSelection },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    enableRowSelection: !!enableSelection,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    ...(pageSize ? { getPaginationRowModel: getPaginationRowModel() } : {}),
    ...(rowId ? { getRowId: (r) => rowId(r) } : {}),
    initialState: pageSize ? { pagination: { pageSize } } : {},
  });

  const rows = table.getRowModel().rows;
  const colCount = table.getVisibleLeafColumns().length;
  const totalRows = table.getFilteredRowModel().rows.length;
  const hideable = table.getAllColumns().filter((c) => c.getCanHide());
  const selected = enableSelection ? table.getSelectedRowModel().rows.map((r) => r.original) : [];
  const filtering = globalFilter.trim().length > 0;

  // Track which row ids existed last render so live-tail only animates genuinely new rows
  // (re-sort / filter / paginate no longer re-animate the whole table).
  const prevIds = React.useRef<Set<string> | null>(null);
  React.useEffect(() => {
    if (!rowId) return;
    prevIds.current = new Set(rows.map((r) => r.id));
  });
  const isNew = (id: string) => !reduceMotion && rowId != null && prevIds.current != null && !prevIds.current.has(id);

  const densityCell = density === "compact" ? "[&_td]:py-1 [&_th]:py-1.5" : "";

  return (
    <div className="space-y-3">
      {(filterPlaceholder || toolbar || hideable.length > 0 || enableDensity) && (
        <div className="flex flex-wrap items-center gap-2">
          {toolbar}
          {filterPlaceholder && (
            <Input
              value={globalFilter}
              onChange={(e) => setGlobalFilter(e.target.value)}
              placeholder={filterPlaceholder}
              aria-label={filterPlaceholder}
              className="h-8 max-w-xs"
            />
          )}
          <div className="ml-auto flex items-center gap-2">
            {enableDensity && (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                aria-label={density === "compact" ? "Switch to comfortable density" : "Switch to compact density"}
                title={density === "compact" ? "Comfortable rows" : "Compact rows"}
                onClick={() => setDensity((d) => (d === "compact" ? "comfortable" : "compact"))}
              >
                {density === "compact" ? <Rows4 className="size-3.5 opacity-70" /> : <Rows3 className="size-3.5 opacity-70" />}
              </Button>
            )}
            {hideable.length > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-1.5">
                    Columns <Columns3 className="size-3.5 opacity-60" />
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
        </div>
      )}

      {/* Contextual bulk-action bar — appears only when rows are selected. */}
      {enableSelection && bulkActions && selected.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-primary/[0.05] px-3 py-2">
          <span className="font-mono text-xs font-medium text-foreground">{selected.length} selected</span>
          <Button variant="ghost" size="sm" className="h-7 gap-1 text-muted-foreground" onClick={() => table.resetRowSelection()}>
            <X className="size-3.5" /> Clear
          </Button>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {bulkActions(selected, () => table.resetRowSelection())}
          </div>
        </div>
      )}

      <div className={cn("overflow-hidden rounded-xl border bg-card", densityCell)} aria-busy={loading || undefined}>
        <Table aria-rowcount={totalRows}>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id}>
                {hg.headers.map((h) => {
                  const sorted = h.column.getIsSorted();
                  return (
                    <TableHead
                      key={h.id}
                      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                      style={{ width: h.getSize() !== 150 ? h.getSize() : undefined }}
                    >
                      {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <tbody data-slot="table-body" className="[&_tr:last-child]:border-0">
            {loading && rows.length === 0 ? (
              Array.from({ length: 6 }).map((_, r) => (
                <tr key={`sk-${r}`} className="border-b">
                  {Array.from({ length: colCount }).map((_c, ci) => (
                    <TableCell key={ci}>
                      <div className="shimmer h-4 w-full max-w-[12rem] rounded bg-muted" />
                    </TableCell>
                  ))}
                </tr>
              ))
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={colCount} className="py-14 text-center text-sm text-muted-foreground">
                  {filtering ? (
                    <div className="flex flex-col items-center gap-2">
                      <span>No records match “{globalFilter}”.</span>
                      <Button variant="outline" size="sm" onClick={() => setGlobalFilter("")}>Clear filters</Button>
                    </div>
                  ) : (
                    empty ?? "No records"
                  )}
                </td>
              </tr>
            ) : (
              rows.map((row) => {
                const animate = isNew(row.id);
                const handlers = {
                  onClick: onRowClick ? () => onRowClick(row.original) : undefined,
                  tabIndex: onRowClick ? 0 : undefined,
                  role: onRowClick ? ("button" as const) : undefined,
                  onKeyDown: onRowClick
                    ? (e: React.KeyboardEvent) => {
                        if (e.key === "Enter" || e.key === " ") {
                          if (e.key === " ") e.preventDefault();
                          onRowClick(row.original);
                        }
                      }
                    : undefined,
                  "data-slot": "table-row",
                  "data-state": row.getIsSelected() ? "selected" : undefined,
                  className: cn(
                    "border-b border-l-2 border-l-transparent transition-colors hover:border-l-primary hover:bg-primary/[0.04] data-[state=selected]:bg-primary/[0.06]",
                    onRowClick && "group cursor-pointer",
                  ),
                };
                const cells = row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                ));
                return animate ? (
                  <motion.tr
                    key={row.id}
                    initial={{ opacity: 0, y: -5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                    {...handlers}
                  >
                    {cells}
                  </motion.tr>
                ) : (
                  <tr key={row.id} {...handlers}>
                    {cells}
                  </tr>
                );
              })
            )}
          </tbody>
        </Table>
      </div>

      {pageSize && rows.length > 0 && (
        <div className="flex items-center justify-between px-1">
          <span className="font-mono text-xs text-muted-foreground">
            {totalRows} rows · page {table.getState().pagination.pageIndex + 1}/{table.getPageCount()}
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
