"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import SbomSelector from "@/components/SbomSelector";
import SbomSummaryCards from "@/components/SbomSummaryCards";
import ComponentsTable from "@/components/ComponentsTable";
import FilterBar from "@/components/FilterBar";
import MetadataPanel from "@/components/MetadataPanel";
import VulnerabilitiesTab from "@/components/VulnerabilitiesTab";
import {
  SbomListItem,
  SbomSummary,
  GroupedComponentsResponse,
  ViewMode,
  Vulnerability,
  VulnerabilitiesResponse,
} from "@/types/SbomTypes";

type Tab = "components" | "vulnerabilities";

function pickView(item: SbomListItem | undefined): ViewMode {
  if (!item) return "sbom";
  if (item.has_merged) return "merged";
  if (item.has_trivy) return "trivy";
  return "sbom";
}

export default function DashboardPage() {
  const [sboms, setSboms] = useState<SbomListItem[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [view, setView] = useState<ViewMode>("sbom");
  const [tab, setTab] = useState<Tab>("components");
  const [summary, setSummary] = useState<SbomSummary | null>(null);
  const [componentsData, setComponentsData] = useState<GroupedComponentsResponse | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnError, setVulnError] = useState<string | null>(null);
  const [type, setType] = useState("library");
  const [name, setName] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);

  const selected = useMemo(
    () => sboms.find((s) => s.id === selectedId),
    [sboms, selectedId]
  );

  useEffect(() => {
    fetch("/api/sboms")
      .then((r) => r.json())
      .then((data: SbomListItem[]) => {
        setSboms(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
          setView(pickView(data[0]));
        }
      });
  }, []);

  useEffect(() => {
    if (!selected) return;
    setView(pickView(selected));
    setOffset(0);
  }, [selected]);

  useEffect(() => {
    if (!selectedId) return;
    const params = new URLSearchParams({ view });
    fetch(`/api/sboms/${selectedId}/summary?${params}`)
      .then((r) => r.json())
      .then((data: SbomSummary) => setSummary(data));
  }, [selectedId, view]);

  const fetchComponents = useCallback(() => {
    if (!selectedId) return;
    setLoading(true);
    const params = new URLSearchParams({
      view,
      type,
      name,
      offset: String(offset),
      limit: "50",
    });
    fetch(`/api/sboms/${selectedId}/components/grouped?${params}`)
      .then((r) => r.json())
      .then((data: GroupedComponentsResponse) => setComponentsData(data))
      .finally(() => setLoading(false));
  }, [selectedId, view, type, name, offset]);

  useEffect(() => {
    fetchComponents();
  }, [fetchComponents]);

  // Fetch vulnerabilities when applicable.
  useEffect(() => {
    if (!selectedId || view === "sbom") {
      setVulnerabilities([]);
      setVulnError(null);
      return;
    }
    let cancelled = false;
    setVulnLoading(true);
    setVulnError(null);
    const params = new URLSearchParams({ view });
    fetch(`/api/sboms/${selectedId}/vulnerabilities?${params}`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = (await r.json()) as
          | VulnerabilitiesResponse
          | Vulnerability[];
        // Backend returns the wrapped shape; default to a graceful empty state.
        if (Array.isArray(data)) return data;
        return data.vulnerabilities ?? [];
      })
      .then((rows) => {
        if (!cancelled) setVulnerabilities(rows);
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : String(e);
          setVulnError(msg);
          setVulnerabilities([]);
        }
      })
      .finally(() => {
        if (!cancelled) setVulnLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, view]);

  const handleTypeChange = (newType: string) => {
    setType(newType);
    setOffset(0);
  };

  const handleNameChange = (newName: string) => {
    setName(newName);
    setOffset(0);
  };

  const handleSbomChange = (id: string) => {
    setSelectedId(id);
    setOffset(0);
  };

  const vulnerabilitiesEnabled = view !== "sbom";

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <SbomSelector sboms={sboms} selected={selectedId} onChange={handleSbomChange} />
      </div>
      <MetadataPanel summary={summary} />
      <SbomSummaryCards summary={summary} />

      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6" aria-label="Tabs">
          <button
            type="button"
            onClick={() => setTab("components")}
            className={`whitespace-nowrap py-2 px-1 border-b-2 text-sm font-medium ${
              tab === "components"
                ? "border-blue-600 text-blue-700"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
            }`}
          >
            Components
          </button>
          <button
            type="button"
            onClick={() => vulnerabilitiesEnabled && setTab("vulnerabilities")}
            disabled={!vulnerabilitiesEnabled}
            title={
              vulnerabilitiesEnabled
                ? "Vulnerability findings from Trivy"
                : "Vulnerabilities are only available in the Trivy or Merged view"
            }
            className={`whitespace-nowrap py-2 px-1 border-b-2 text-sm font-medium ${
              !vulnerabilitiesEnabled
                ? "border-transparent text-gray-300 cursor-not-allowed"
                : tab === "vulnerabilities"
                ? "border-blue-600 text-blue-700"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
            }`}
          >
            Vulnerabilities
            {vulnerabilitiesEnabled && vulnerabilities.length > 0 && (
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-200 text-gray-800">
                {vulnerabilities.length}
              </span>
            )}
          </button>
        </nav>
      </div>

      {tab === "components" && (
        <div className="space-y-4">
          <FilterBar
            type={type}
            name={name}
            onTypeChange={handleTypeChange}
            onNameChange={handleNameChange}
          />
          {loading ? (
            <div className="text-center py-8 text-gray-500">Loading...</div>
          ) : componentsData ? (
            <ComponentsTable
              components={componentsData.components}
              total={componentsData.total}
              offset={componentsData.offset}
              limit={componentsData.limit}
              onPageChange={setOffset}
            />
          ) : null}
        </div>
      )}

      {tab === "vulnerabilities" && vulnerabilitiesEnabled && (
        <div className="space-y-4">
          {vulnLoading ? (
            <div className="text-center py-8 text-gray-500">Loading...</div>
          ) : vulnError ? (
            <div className="text-center py-8 text-red-600">
              Failed to load vulnerabilities: {vulnError}
            </div>
          ) : (
            <VulnerabilitiesTab
              sbomId={selectedId}
              view={view}
              vulnerabilities={vulnerabilities}
            />
          )}
        </div>
      )}
    </div>
  );
}
