"use client";

import { SbomListItem } from "@/types/SbomTypes";

interface Props {
  sboms: SbomListItem[];
  selected: string;
  onChange: (id: string) => void;
}

export default function SbomSelector({ sboms, selected, onChange }: Props) {
  return (
    <div className="flex items-center gap-3">
      <label htmlFor="sbom-select" className="text-sm font-medium text-gray-700">
        SBOM Report:
      </label>
      <select
        id="sbom-select"
        value={selected}
        onChange={(e) => onChange(e.target.value)}
        className="border border-gray-300 rounded-md px-3 py-2 text-sm bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        <option value="">Select a report...</option>
        {sboms.map((s) => (
          <option key={s.id} value={s.id}>
            {s.image}:{s.version}
          </option>
        ))}
      </select>
    </div>
  );
}
