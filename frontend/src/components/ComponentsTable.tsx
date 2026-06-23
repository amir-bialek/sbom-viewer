"use client";

import { useState, useMemo } from "react";
import { GroupedComponent } from "@/types/SbomTypes";

type SortKey = "name" | "version" | "type" | "count" | "licenses" | "source";
type SortDir = "asc" | "desc";

interface Props {
  components: GroupedComponent[];
  total: number;
  offset: number;
  limit: number;
  onPageChange: (newOffset: number) => void;
}

export default function ComponentsTable({
  components,
  total,
  offset,
  limit,
  onPageChange,
}: Props) {
  const [sortKey, setSortKey] = useState<SortKey | null>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [tooltip, setTooltip] = useState<{ text: string; top: number; left: number } | null>(null);

  const hasSourceColumn = useMemo(
    () => components.some((c) => !!c.installed_via && c.installed_via !== ""),
    [components]
  );

  const columns: { label: string; key: SortKey; tooltip?: string }[] = useMemo(() => {
    const cols: { label: string; key: SortKey; tooltip?: string }[] = [
      { label: "Name", key: "name" },
      { label: "Version", key: "version" },
      { label: "Type", key: "type" },
      { label: "Occurrences", key: "count", tooltip: "Number of times this component appears across the image" },
      { label: "Licenses", key: "licenses" },
    ];
    if (hasSourceColumn) {
      cols.push({
        label: "Source",
        key: "source",
        tooltip: "Annex B source for this component (e.g. OS package, language ecosystem)",
      });
    }
    return cols;
  }, [hasSourceColumn]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d: SortDir) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const sorted = useMemo(() => {
    if (!sortKey) return components;
    return [...components].sort((a, b) => {
      let cmp: number;
      switch (sortKey) {
        case "count":
          cmp = a.count - b.count;
          break;
        case "licenses":
          cmp = a.licenses.join(", ").localeCompare(b.licenses.join(", "));
          break;
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "version":
          cmp = a.version.localeCompare(b.version);
          break;
        case "type":
          cmp = a.type.localeCompare(b.type);
          break;
        case "source":
          cmp = (a.installed_via || "").localeCompare(b.installed_via || "");
          break;
        default:
          cmp = 0;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [components, sortKey, sortDir]);

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit);
  const colCount = columns.length;

  return (
    <>
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  onClick={() => handleSort(col.key)}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  {col.label}
                  {col.tooltip && (
                    <span
                      className="ml-1"
                      onClick={(e) => e.stopPropagation()}
                      onMouseEnter={(e) => {
                        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                        setTooltip({ text: col.tooltip!, top: rect.bottom + 6, left: rect.left + rect.width / 2 });
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    >
                      <span className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full bg-gray-200 text-gray-500 text-[10px] font-bold leading-none">?</span>
                    </span>
                  )}
                  {sortKey === col.key && (
                    <span className="ml-1">{sortDir === "asc" ? "▲" : "▼"}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {sorted.map((c, idx) => (
              <tr key={`${c.name}-${c.version}-${idx}`} className="hover:bg-gray-50">
                <td className="px-4 py-2 font-medium text-gray-900">{c.name}</td>
                <td className="px-4 py-2 text-gray-600">{c.version}</td>
                <td className="px-4 py-2 text-gray-600">{c.type}</td>
                <td className="px-4 py-2">
                  {c.count > 1 ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-200 text-gray-800">
                      {c.count}
                    </span>
                  ) : (
                    <span className="text-gray-500">1</span>
                  )}
                </td>
                <td className="px-4 py-2 text-gray-600">
                  {c.licenses.length > 0 ? c.licenses.join(", ") : "-"}
                </td>
                {hasSourceColumn && (
                  <td className="px-4 py-2 text-gray-600">
                    {c.installed_via || "-"}
                  </td>
                )}
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={colCount} className="px-4 py-8 text-center text-gray-500">
                  No components found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
        <p className="text-sm text-gray-600">
          Showing {offset + 1}-{Math.min(offset + limit, total)} of {total.toLocaleString()}
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onPageChange(Math.max(0, offset - limit))}
            disabled={offset === 0}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
          >
            Previous
          </button>
          <span className="text-sm text-gray-600">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => onPageChange(offset + limit)}
            disabled={offset + limit >= total}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
          >
            Next
          </button>
        </div>
      </div>
    </div>
    {tooltip && (
      <div
        className="fixed z-50 px-3 py-2 text-xs text-white bg-gray-800 rounded shadow-lg w-48 -translate-x-1/2"
        style={{ top: tooltip.top, left: tooltip.left }}
      >
        {tooltip.text}
      </div>
    )}
    </>
  );
}
