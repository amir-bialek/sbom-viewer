"use client";

import { useState, useEffect, useCallback } from "react";
import SbomSelector from "@/components/SbomSelector";
import SbomSummaryCards from "@/components/SbomSummaryCards";
import ComponentsTable from "@/components/ComponentsTable";
import FilterBar from "@/components/FilterBar";
import MetadataPanel from "@/components/MetadataPanel";
import { SbomListItem, SbomSummary, GroupedComponentsResponse } from "@/types/SbomTypes";

export default function DashboardPage() {
  const [sboms, setSboms] = useState<SbomListItem[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [summary, setSummary] = useState<SbomSummary | null>(null);
  const [componentsData, setComponentsData] = useState<GroupedComponentsResponse | null>(null);
  const [type, setType] = useState("library");
  const [name, setName] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("/api/sboms")
      .then((r) => r.json())
      .then((data: SbomListItem[]) => {
        setSboms(data);
        if (data.length > 0) {
          setSelectedId(data[0].id);
        }
      });
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    fetch(`/api/sboms/${selectedId}/summary`)
      .then((r) => r.json())
      .then((data: SbomSummary) => setSummary(data));
  }, [selectedId]);

  const fetchComponents = useCallback(() => {
    if (!selectedId) return;
    setLoading(true);
    const params = new URLSearchParams({
      type,
      name,
      offset: String(offset),
      limit: "100",
    });
    fetch(`/api/sboms/${selectedId}/components/grouped?${params}`)
      .then((r) => r.json())
      .then((data: GroupedComponentsResponse) => setComponentsData(data))
      .finally(() => setLoading(false));
  }, [selectedId, type, name, offset]);

  useEffect(() => {
    fetchComponents();
  }, [fetchComponents]);

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

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <SbomSelector sboms={sboms} selected={selectedId} onChange={handleSbomChange} />
      <MetadataPanel summary={summary} />
      <SbomSummaryCards summary={summary} />
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
    </div>
  );
}
