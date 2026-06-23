"use client";

import { SbomSummary } from "@/types/SbomTypes";

interface Props {
  summary: SbomSummary | null;
}

const SEVERITY_TONE: Record<string, string> = {
  Critical: "text-red-700",
  High: "text-orange-700",
  Medium: "text-yellow-700",
  Low: "text-blue-700",
  Unknown: "text-gray-700",
};

export default function SbomSummaryCards({ summary }: Props) {
  if (!summary) return null;

  const licensePercent =
    summary.total_components > 0
      ? ((summary.with_licenses / summary.total_components) * 100).toFixed(1)
      : "0";

  const baseCards = [
    { label: "Total Components", value: summary.total_components.toLocaleString(), tooltip: "Total number of components (libraries, files, frameworks, etc.) found in the container image" },
    { label: "Libraries", value: (summary.by_type["library"] || 0).toLocaleString(), tooltip: "Number of software libraries (packages, dependencies) detected in the image" },
    { label: "Files", value: (summary.by_type["file"] || 0).toLocaleString(), tooltip: "Number of individual files identified as components in the image" },
    { label: "License Coverage", value: `${licensePercent}%`, tooltip: "Percentage of components that have a declared software license" },
    { label: "With PURL", value: summary.with_purl.toLocaleString(), tooltip: "Number of components with a Package URL (PURL) — a standardized identifier for locating packages in external registries" },
  ];

  const counts = summary.vulnerability_counts;
  const severityCards = counts
    ? [
        { label: "Critical", value: counts.critical.toLocaleString(), tooltip: "Number of Critical-severity vulnerabilities reported by Trivy", tone: "Critical" },
        { label: "High", value: counts.high.toLocaleString(), tooltip: "Number of High-severity vulnerabilities reported by Trivy", tone: "High" },
        { label: "Medium", value: counts.medium.toLocaleString(), tooltip: "Number of Medium-severity vulnerabilities reported by Trivy", tone: "Medium" },
        { label: "Low", value: counts.low.toLocaleString(), tooltip: "Number of Low-severity vulnerabilities reported by Trivy", tone: "Low" },
        { label: "Unknown", value: counts.unknown.toLocaleString(), tooltip: "Vulnerabilities with no reported severity", tone: "Unknown" },
      ]
    : [];

  const cards = [
    ...baseCards.map((c) => ({ ...c, tone: undefined as string | undefined })),
    ...severityCards,
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm"
        >
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide flex items-center gap-1">
            {card.label}
            <span className="relative group">
              <span className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full bg-gray-200 text-gray-500 text-[10px] font-bold leading-none">?</span>
              <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block w-48 p-2 text-xs text-white bg-gray-800 rounded shadow-lg normal-case tracking-normal z-10">{card.tooltip}</span>
            </span>
          </p>
          <p
            className={`mt-1 text-2xl font-semibold ${
              card.tone ? SEVERITY_TONE[card.tone] : "text-gray-900"
            }`}
          >
            {card.value}
          </p>
        </div>
      ))}
    </div>
  );
}
