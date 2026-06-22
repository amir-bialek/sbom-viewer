export type ViewMode = "sbom" | "trivy" | "merged";

export interface SbomListItem {
  id: string;
  image: string;
  version: string;
  timestamp: string;
  has_sbom: boolean;
  has_trivy: boolean;
  has_merged: boolean;
}

export interface VulnerabilityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface AnnexB {
  date_of_acquisition: string;
  image_ref: string;
  product_name: string;
  product_version: string;
  modifications: string;
}

export interface SbomSummary {
  image: string;
  version: string;
  timestamp: string;
  total_components: number;
  by_type: Record<string, number>;
  with_licenses: number;
  with_purl: number;
  tool: string;
  vulnerability_counts?: VulnerabilityCounts;
  annex_b?: AnnexB;
}

export interface SbomComponent {
  name: string;
  version: string;
  type: string;
  purl: string;
  licenses: string[];
  annex_b_source?: string;
}

export interface ComponentsResponse {
  total: number;
  offset: number;
  limit: number;
  components: SbomComponent[];
}

export interface GroupedComponent {
  name: string;
  version: string;
  type: string;
  licenses: string[];
  purls: string[];
  count: number;
  annex_b_source?: string;
}

export interface GroupedComponentsResponse {
  total: number;
  offset: number;
  limit: number;
  components: GroupedComponent[];
}

export interface AffectedComponent {
  name: string;
  version: string;
  purl: string;
  bom_ref: string;
  versions?: { version?: string; status?: string }[];
}

export interface Vulnerability {
  id: string;
  severity: string;
  score: number | null;
  source: string;
  fixed_version: string;
  description: string;
  published: string;
  updated: string;
  affected_components: AffectedComponent[];
}

export interface VulnerabilityRating {
  source?: { name?: string; url?: string };
  score?: number;
  severity?: string;
  method?: string;
  vector?: string;
  justification?: string;
}

export interface VulnerabilityDetail extends Vulnerability {
  cwes: number[];
  advisories: { title?: string; url?: string }[];
  ratings: VulnerabilityRating[];
}

export interface VulnerabilitiesResponse {
  vulnerabilities: Vulnerability[];
}
