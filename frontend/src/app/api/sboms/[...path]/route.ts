import { NextRequest, NextResponse } from "next/server";

const BACKEND_API_URL = process.env.BACKEND_API_URL || "http://backend:8000";

const ALLOWED_ACTIONS = new Set([
  "summary",
  "components",
  "components/grouped",
  "vulnerabilities",
  "annex-b",
]);

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;

  let action: string;
  let sbomId: string;

  // Two-segment actions handled the same way as components/grouped:
  //   <id...>/components/grouped
  //   <id...>/vulnerabilities/<cve>
  const lastSegment = path[path.length - 1];
  const secondLast = path.length >= 2 ? path[path.length - 2] : "";

  if (secondLast === "components" && lastSegment === "grouped") {
    action = "components/grouped";
    sbomId = path.slice(0, -2).join("/");
  } else if (secondLast === "vulnerabilities") {
    action = `vulnerabilities/${lastSegment}`;
    sbomId = path.slice(0, -2).join("/");
  } else {
    action = lastSegment;
    sbomId = path.slice(0, -1).join("/");
  }

  const actionBase = action.startsWith("vulnerabilities/")
    ? "vulnerabilities"
    : action;

  if (!ALLOWED_ACTIONS.has(actionBase) && action !== "components/grouped") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  if (!sbomId) {
    return NextResponse.json({ error: "Missing sbom_id" }, { status: 400 });
  }

  const searchParams = request.nextUrl.searchParams;
  const query = new URLSearchParams();
  for (const [key, value] of searchParams.entries()) {
    query.set(key, value);
  }
  const qs = query.toString();
  const url = `${BACKEND_API_URL}/api/sboms/${sbomId}/${action}${qs ? `?${qs}` : ""}`;

  const res = await fetch(url, { cache: "no-store" });
  const data = await res.json().catch(() => ({}));
  return NextResponse.json(data, { status: res.status });
}
