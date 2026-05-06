"use client";

interface Props {
  type: string;
  name: string;
  onTypeChange: (type: string) => void;
  onNameChange: (name: string) => void;
}

const COMPONENT_TYPES = ["library", "file", "application", "operating-system"];

export default function FilterBar({ type, name, onTypeChange, onNameChange }: Props) {
  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="flex items-center gap-2">
        <label htmlFor="type-filter" className="text-sm font-medium text-gray-700">
          Type:
        </label>
        <select
          id="type-filter"
          value={type}
          onChange={(e) => onTypeChange(e.target.value)}
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {COMPONENT_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <label htmlFor="name-filter" className="text-sm font-medium text-gray-700">
          Name:
        </label>
        <input
          id="name-filter"
          type="text"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="Search by name..."
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
        />
      </div>
    </div>
  );
}
