"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import {
  Vulnerability,
  VulnerabilityDetail,
  ViewMode,
} from "@/types/SbomTypes";

interface Props {
  sbomId: string;
  view: ViewMode;
  vulnerabilities: Vulnerability[];
}

type SortKey =
  | "id"
  | "severity"
  | "score"
  | "package"
  | "installed_via"
  | "source"
  | "affected"
  | "published"
  | "fix";
type SortDir = "asc" | "desc";

const PAGE_SIZE = 50;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
  "": 0,
};

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  low: "bg-blue-100 text-blue-800 border-blue-200",
  unknown: "bg-gray-100 text-gray-700 border-gray-200",
};

function severityLabel(s: string): string {
  if (!s) return "unknown";
  return s.toLowerCase();
}

function SeverityPill({ severity }: { severity: string }) {
  const key = severityLabel(severity);
  const cls = SEVERITY_PILL[key] || SEVERITY_PILL.unknown;
  const display = severity || "unknown";
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cls}`}
    >
      {display}
    </span>
  );
}

function truncate(s: string, n = 120): string {
  if (!s) return "";
  return s.length > n ? `${s.slice(0, n).trimEnd()}…` : s;
}

function formatDate(s: string): string {
  if (!s) return "-";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString();
}

function packageLabel(v: Vulnerability): string {
  const list = v.affected_components;
  if (list.length === 0) return "";
  const first = list[0];
  const head = `${first.name} ${first.version}`.trim();
  if (list.length > 1) {
    return `${head} + ${list.length - 1} more`;
  }
  return head;
}

function packageSortKey(v: Vulnerability): string {
  const first = v.affected_components[0];
  return first ? first.name : "";
}

function installedViaValues(v: Vulnerability): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of v.affected_components) {
    const s = c.installed_via || "";
    if (s && !seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}

function installedViaSortKey(v: Vulnerability): string {
  const vals = installedViaValues(v);
  return vals[0] ?? "";
}

export default function VulnerabilitiesTab({
  sbomId,
  view,
  vulnerabilities,
}: Props) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [detail, setDetail] = useState<VulnerabilityDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  useEffect(() => {
    setPage(0);
  }, [severityFilter, sortKey, sortDir, vulnerabilities]);

  const filtered = useMemo(() => {
    if (severityFilter === "all") return vulnerabilities;
    return vulnerabilities.filter(
      (v) => severityLabel(v.severity) === severityFilter
    );
  }, [vulnerabilities, severityFilter]);

  const sorted = useMemo(() => {
    const rows = [...filtered];
    rows.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "id":
          cmp = a.id.localeCompare(b.id);
          break;
        case "severity":
          cmp =
            (SEVERITY_ORDER[severityLabel(a.severity)] ?? 0) -
            (SEVERITY_ORDER[severityLabel(b.severity)] ?? 0);
          break;
        case "score": {
          const sa = a.score ?? -1;
          const sb = b.score ?? -1;
          cmp = sa - sb;
          break;
        }
        case "package":
          cmp = packageSortKey(a).localeCompare(packageSortKey(b));
          break;
        case "installed_via":
          cmp = installedViaSortKey(a).localeCompare(installedViaSortKey(b));
          break;
        case "source":
          cmp = a.source.localeCompare(b.source);
          break;
        case "affected":
          cmp = a.affected_components.length - b.affected_components.length;
          break;
        case "published":
          cmp = a.published.localeCompare(b.published);
          break;
        case "fix": {
          const fa = a.fixed_version ? 1 : 0;
          const fb = b.fixed_version ? 1 : 0;
          cmp = fa - fb;
          break;
        }
        default:
          cmp = 0;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return rows;
  }, [filtered, sortKey, sortDir]);

  const total = sorted.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const offset = safePage * PAGE_SIZE;
  const pageRows = sorted.slice(offset, offset + PAGE_SIZE);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "severity" || key === "score" ? "desc" : "asc");
    }
  };

  useEffect(() => {
    if (!selectedCve) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    setDetailError(null);
    fetch(
      `/api/sboms/${sbomId}/vulnerabilities/${encodeURIComponent(
        selectedCve
      )}?view=${view}`
    )
      .then(async (r) => {
        if (!r.ok) {
          throw new Error(`HTTP ${r.status}`);
        }
        return (await r.json()) as VulnerabilityDetail;
      })
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : String(e);
          setDetailError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedCve, sbomId, view]);

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (
      <span className="ml-1">{sortDir === "asc" ? "▲" : "▼"}</span>
    ) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <label
            htmlFor="severity-filter"
            className="text-sm font-medium text-gray-700"
          >
            Severity:
          </label>
          <select
            id="severity-filter"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-1.5 text-sm bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>
        <p className="text-sm text-gray-600">
          {sorted.length} of {vulnerabilities.length} vulnerabilities
        </p>
      </div>

      <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th
                  onClick={() => handleSort("id")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  CVE
                  {sortIndicator("id")}
                </th>
                <th
                  onClick={() => handleSort("severity")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Severity
                  {sortIndicator("severity")}
                </th>
                <th
                  onClick={() => handleSort("score")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  CVSS
                  {sortIndicator("score")}
                </th>
                <th
                  onClick={() => handleSort("package")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Package
                  {sortIndicator("package")}
                </th>
                <th
                  onClick={() => handleSort("installed_via")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Installed via
                  {sortIndicator("installed_via")}
                </th>
                <th
                  onClick={() => handleSort("source")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Published by
                  {sortIndicator("source")}
                </th>
                <th
                  onClick={() => handleSort("affected")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Affected
                  {sortIndicator("affected")}
                </th>
                <th
                  onClick={() => handleSort("published")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100"
                >
                  Published date
                  {sortIndicator("published")}
                </th>
                <th
                  onClick={() => handleSort("fix")}
                  className="text-left px-4 py-3 font-medium text-gray-700 cursor-pointer select-none hover:bg-gray-100 max-w-[12rem]"
                >
                  Fix
                  {sortIndicator("fix")}
                </th>
                <th className="text-left px-4 py-3 font-medium text-gray-700">
                  Description
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {pageRows.map((v) => {
                const isOpen = !!expanded[v.id];
                return (
                  <Fragment key={v.id}>
                    <tr
                      className="hover:bg-gray-50 cursor-pointer"
                      onClick={() => setSelectedCve(v.id)}
                    >
                      <td className="px-4 py-2 font-medium text-blue-700 underline">
                        {v.id}
                      </td>
                      <td className="px-4 py-2">
                        <SeverityPill severity={v.severity} />
                      </td>
                      <td className="px-4 py-2 text-gray-700">
                        {v.score !== null ? v.score.toFixed(1) : "-"}
                      </td>
                      <td className="px-4 py-2 text-gray-700">
                        {packageLabel(v) || "-"}
                      </td>
                      <td className="px-4 py-2 text-gray-700">
                        {installedViaValues(v).join(", ") || "-"}
                      </td>
                      <td className="px-4 py-2 text-gray-700">
                        {v.source || "-"}
                      </td>
                      <td className="px-4 py-2 text-gray-700">
                        {v.affected_components.length > 0 ? (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setExpanded((prev) => ({
                                ...prev,
                                [v.id]: !prev[v.id],
                              }));
                            }}
                            className="text-blue-700 hover:underline"
                          >
                            {v.affected_components.length}
                            <span className="ml-1 text-xs text-gray-500">
                              {isOpen ? "▲" : "▼"}
                            </span>
                          </button>
                        ) : (
                          "0"
                        )}
                      </td>
                      <td className="px-4 py-2 text-gray-600">
                        {formatDate(v.published)}
                      </td>
                      <td className="px-4 py-2 text-gray-700 max-w-[12rem] truncate" title={v.fixed_version || undefined}>
                        {v.fixed_version ? (
                          <span className="text-green-700">
                            {v.fixed_version}
                          </span>
                        ) : (
                          <span className="text-gray-400">No</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-gray-600 max-w-md">
                        {truncate(v.description)}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-gray-50">
                        <td colSpan={10} className="px-4 py-3">
                          <ul className="text-xs text-gray-700 space-y-1">
                            {v.affected_components.map((c, idx) => (
                              <li
                                key={`${c.bom_ref}-${idx}`}
                                className="font-mono"
                              >
                                {c.name}@{c.version}
                                {c.purl ? (
                                  <span className="ml-2 text-gray-500">
                                    {c.purl}
                                  </span>
                                ) : null}
                              </li>
                            ))}
                          </ul>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {sorted.length === 0 && (
                <tr>
                  <td
                    colSpan={10}
                    className="px-4 py-8 text-center text-gray-500"
                  >
                    No vulnerabilities found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {total > 0 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
            <p className="text-sm text-gray-600">
              Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of{" "}
              {total.toLocaleString()}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={safePage === 0}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
              >
                Previous
              </button>
              <span className="text-sm text-gray-600">
                Page {safePage + 1} of {totalPages}
              </span>
              <button
                onClick={() =>
                  setPage((p) => Math.min(totalPages - 1, p + 1))
                }
                disabled={safePage >= totalPages - 1}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded-md bg-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-100"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {selectedCve && (
        <VulnerabilityDetailModal
          cveId={selectedCve}
          detail={detail}
          loading={detailLoading}
          error={detailError}
          onClose={() => setSelectedCve(null)}
        />
      )}
    </div>
  );
}

interface ModalProps {
  cveId: string;
  detail: VulnerabilityDetail | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
}

function VulnerabilityDetailModal({
  cveId,
  detail,
  loading,
  error,
  onClose,
}: ModalProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      onClick={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-xl max-w-3xl w-full max-h-[85vh] overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200">
          <h2 className="text-base font-semibold text-gray-900">{cveId}</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-800 text-xl leading-none"
            aria-label="Close"
          >
            &times;
          </button>
        </div>
        <div className="px-5 py-4 overflow-y-auto space-y-5">
          {loading && (
            <p className="text-sm text-gray-500">Loading details…</p>
          )}
          {error && (
            <p className="text-sm text-red-600">
              Failed to load details: {error}
            </p>
          )}
          {detail && (
            <>
              <section>
                <h3 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Summary
                </h3>
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-xs text-gray-500">Severity</dt>
                    <dd className="mt-0.5">
                      <SeverityPill severity={detail.severity} />
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">CVSS</dt>
                    <dd className="mt-0.5 text-gray-900">
                      {detail.score !== null ? detail.score.toFixed(1) : "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Published by</dt>
                    <dd className="mt-0.5 text-gray-900">
                      {detail.source || "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Fix</dt>
                    <dd className="mt-0.5 text-gray-900">
                      {detail.fixed_version || "No fix listed"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Published date</dt>
                    <dd className="mt-0.5 text-gray-900">
                      {formatDate(detail.published)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500">Updated</dt>
                    <dd className="mt-0.5 text-gray-900">
                      {formatDate(detail.updated)}
                    </dd>
                  </div>
                </dl>
              </section>

              {detail.description && (
                <section>
                  <h3 className="text-xs font-semibold uppercase text-gray-500 mb-1">
                    Description
                  </h3>
                  <p className="text-sm text-gray-800 whitespace-pre-wrap">
                    {detail.description}
                  </p>
                </section>
              )}

              <section>
                <h3 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Ratings ({detail.ratings.length})
                </h3>
                {detail.ratings.length === 0 ? (
                  <p className="text-sm text-gray-500">No ratings reported.</p>
                ) : (
                  <div className="overflow-x-auto border border-gray-200 rounded">
                    <table className="w-full text-xs">
                      <thead className="bg-gray-50 border-b border-gray-200">
                        <tr>
                          <th className="text-left px-3 py-2 font-medium text-gray-700">
                            Source
                          </th>
                          <th className="text-left px-3 py-2 font-medium text-gray-700">
                            Severity
                          </th>
                          <th className="text-left px-3 py-2 font-medium text-gray-700">
                            Score
                          </th>
                          <th className="text-left px-3 py-2 font-medium text-gray-700">
                            Method
                          </th>
                          <th className="text-left px-3 py-2 font-medium text-gray-700">
                            Vector
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100">
                        {detail.ratings.map((r, i) => (
                          <tr key={i}>
                            <td className="px-3 py-2 text-gray-700">
                              {r.source?.name || "-"}
                            </td>
                            <td className="px-3 py-2">
                              <SeverityPill severity={r.severity || ""} />
                            </td>
                            <td className="px-3 py-2 text-gray-700">
                              {typeof r.score === "number"
                                ? r.score.toFixed(1)
                                : "-"}
                            </td>
                            <td className="px-3 py-2 text-gray-700">
                              {r.method || "-"}
                            </td>
                            <td className="px-3 py-2 text-gray-600 font-mono break-all">
                              {r.vector || "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section>
                <h3 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Advisories ({detail.advisories.length})
                </h3>
                {detail.advisories.length === 0 ? (
                  <p className="text-sm text-gray-500">
                    No advisories reported.
                  </p>
                ) : (
                  <ul className="text-sm space-y-1">
                    {detail.advisories.map((a, i) => (
                      <li key={i}>
                        {a.url ? (
                          <a
                            href={a.url}
                            target="_blank"
                            rel="noreferrer noopener"
                            className="text-blue-700 hover:underline break-all"
                          >
                            {a.title || a.url}
                          </a>
                        ) : (
                          <span className="text-gray-700">
                            {a.title || "(no link)"}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              <section>
                <h3 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                  Affected components ({detail.affected_components.length})
                </h3>
                <ul className="text-xs space-y-1 font-mono">
                  {detail.affected_components.map((c, i) => (
                    <li key={`${c.bom_ref}-${i}`} className="text-gray-700">
                      {c.name}@{c.version}
                      {c.purl ? (
                        <span className="ml-2 text-gray-500">{c.purl}</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </section>

              {detail.cwes.length > 0 && (
                <section>
                  <h3 className="text-xs font-semibold uppercase text-gray-500 mb-2">
                    CWEs
                  </h3>
                  <p className="text-sm text-gray-800">
                    {detail.cwes.map((c) => `CWE-${c}`).join(", ")}
                  </p>
                </section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
