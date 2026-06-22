"use client";

import { ViewMode } from "@/types/SbomTypes";

interface Props {
  view: ViewMode;
  hasSbom: boolean;
  hasTrivy: boolean;
  hasMerged: boolean;
  onChange: (view: ViewMode) => void;
}

const DISABLED_TOOLTIP =
  "This image was scanned before enrichment was enabled";

const OPTIONS: { value: ViewMode; label: string }[] = [
  { value: "sbom", label: "SBOM" },
  { value: "trivy", label: "Trivy" },
  { value: "merged", label: "Merged" },
];

export default function ViewModeToggle({
  view,
  hasSbom,
  hasTrivy,
  hasMerged,
  onChange,
}: Props) {
  const available: Record<ViewMode, boolean> = {
    sbom: hasSbom,
    trivy: hasTrivy,
    merged: hasMerged,
  };

  return (
    <div className="inline-flex rounded-md border border-gray-300 bg-white shadow-sm overflow-hidden">
      {OPTIONS.map((opt) => {
        const enabled = available[opt.value];
        const active = view === opt.value;
        const base =
          "px-3 py-1.5 text-sm font-medium border-r border-gray-300 last:border-r-0 focus:outline-none";
        const stateClass = !enabled
          ? "bg-gray-100 text-gray-400 cursor-not-allowed"
          : active
          ? "bg-blue-600 text-white"
          : "bg-white text-gray-700 hover:bg-gray-50";
        return (
          <button
            key={opt.value}
            type="button"
            disabled={!enabled}
            onClick={() => enabled && onChange(opt.value)}
            title={enabled ? `Show ${opt.label} view` : DISABLED_TOOLTIP}
            aria-pressed={active}
            className={`${base} ${stateClass}`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
