// Reusable, table-agnostic filtering + sorting primitives shared across the console.
import { useState } from "react";

/** Search box with a leading glyph and a one-click clear. */
export function SearchInput({
  value,
  onChange,
  placeholder,
  width,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  width?: number;
}) {
  return (
    <div className="search" style={width ? { minWidth: width } : undefined}>
      <span className="search-ico" aria-hidden>
        ⌕
      </span>
      <input
        className="input search-input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
      />
      {value && (
        <button className="search-clear" onClick={() => onChange("")} title="Clear" aria-label="Clear search">
          ✕
        </button>
      )}
    </div>
  );
}

export interface SegOption {
  value: string;
  label: string;
  count?: number;
  /** status-tag class for a colored dot, e.g. "st-online". */
  dot?: string;
}

/** Segmented control — tabbed filter with live counts (e.g. All / Online / Offline). */
export function Segmented({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: SegOption[];
}) {
  return (
    <div className="seg" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={value === o.value}
          className={`seg-item${value === o.value ? " on" : ""}`}
          onClick={() => onChange(o.value)}
        >
          {o.dot && <span className={`seg-dot ${o.dot}`} />}
          {o.label}
          {o.count != null && <span className="seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

/** Clickable, sort-indicating table header cell. */
export function SortHeader({
  k,
  label,
  sortKey,
  dir,
  onSort,
  align,
}: {
  k: string;
  label: string;
  sortKey: string;
  dir: 1 | -1;
  onSort: (k: string) => void;
  align?: "right";
}) {
  const active = k === sortKey;
  return (
    <th
      className={`th-sort${active ? " on" : ""}`}
      onClick={() => onSort(k)}
      style={align ? { textAlign: align } : undefined}
      title={`Sort by ${label}`}
    >
      <span className="th-label">
        {label}
        <span className="th-caret">{active ? (dir === 1 ? "▲" : "▼") : "↕"}</span>
      </span>
    </th>
  );
}

/** Sort state + a stable, null-safe comparator that sorts numbers numerically. */
export function useTableSort<T>(initialKey: string, initialDir: 1 | -1 = 1) {
  const [sortKey, setSortKey] = useState(initialKey);
  const [dir, setDir] = useState<1 | -1>(initialDir);

  const toggle = (k: string) => {
    if (k === sortKey) setDir((d) => (d === 1 ? -1 : 1));
    else {
      setSortKey(k);
      setDir(1);
    }
  };

  const sort = (rows: T[], get: (row: T, key: string) => string | number | null | undefined) =>
    [...rows].sort((a, b) => {
      const va = get(a, sortKey);
      const vb = get(b, sortKey);
      if (va == null && vb == null) return 0;
      if (va == null) return 1; // nulls sink regardless of direction
      if (vb == null) return -1;
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * dir;
      return String(va).localeCompare(String(vb)) * dir;
    });

  return { sortKey, dir, toggle, sort };
}

/** Case-insensitive substring match of `q` against the joined haystack fields. */
export function matchText(q: string, ...fields: (string | number | null | undefined)[]): boolean {
  if (!q) return true;
  return fields
    .map((f) => (f == null ? "" : String(f)))
    .join(" ")
    .toLowerCase()
    .includes(q.toLowerCase());
}
