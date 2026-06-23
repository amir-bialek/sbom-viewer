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

  const annex = summary.annex_b;
  const annexItems = annex
    ? [
        { label: "Date of Acquisition", value: annex.date_of_acquisition },
        { label: "Image Ref", value: annex.image_ref },
        { label: "Product Name", value: annex.product_name },
        { label: "Product Version", value: annex.product_version },
        { label: "Modifications", value: annex.modifications },
      ]
    : [];

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Metadata</h3>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {items.map((item) => (
            <div key={item.label}>
              <dt className="text-xs text-gray-500">{item.label}</dt>
              <dd className="text-sm font-medium text-gray-900 mt-0.5 break-words">
                {item.value || "-"}
              </dd>
            </div>
          ))}
        </dl>
      </div>
      {annex && (
        <div className="pt-3 border-t border-gray-200">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">
            Annex B
          </h3>
          <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {annexItems.map((item) => (
              <div key={item.label}>
                <dt className="text-xs text-gray-500">{item.label}</dt>
                <dd className="text-sm font-medium text-gray-900 mt-0.5 break-words">
                  {item.value || "-"}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
