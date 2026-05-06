"use client";

import { SbomSummary } from "@/types/SbomTypes";

interface Props {
  summary: SbomSummary | null;
}

export default function MetadataPanel({ summary }: Props) {
  if (!summary) return null;

  const items = [
    { label: "Image", value: summary.image },
    { label: "Tag", value: summary.version },
    { label: "Scan Time", value: new Date(summary.timestamp).toLocaleString() },
    { label: "Tool", value: summary.tool },
  ];

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm">
      <h3 className="text-sm font-semibold text-gray-700 mb-3">Metadata</h3>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {items.map((item) => (
          <div key={item.label}>
            <dt className="text-xs text-gray-500">{item.label}</dt>
            <dd className="text-sm font-medium text-gray-900 mt-0.5">{item.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
