export interface SbomListItem {
  id: string;
  image: string;
  version: string;
  timestamp: string;
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
}

export interface SbomComponent {
  name: string;
  version: string;
  type: string;
  purl: string;
  licenses: string[];
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
}

export interface GroupedComponentsResponse {
  total: number;
  offset: number;
  limit: number;
  components: GroupedComponent[];
}
