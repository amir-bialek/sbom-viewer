import { NextRequest, NextResponse } from "next/server";

const BACKEND_API_URL = process.env.BACKEND_API_URL || "http://backend:8000";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const lastSegment = path[path.length - 1];

  let action: string;
  let sbomId: string;

  if (lastSegment === "grouped") {
    action = "components/grouped";
    sbomId = path.slice(0, -2).join("/");
  } else {
    action = lastSegment;
    sbomId = path.slice(0, -1).join("/");
  }

  if (action !== "summary" && action !== "components" && action !== "components/grouped") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  if (!sbomId) {
    return NextResponse.json({ error: "Missing sbom_id" }, { status: 400 });
  }

  if (action === "summary") {
    const res = await fetch(
      `${BACKEND_API_URL}/api/sboms/${sbomId}/summary`,
      { cache: "no-store" }
    );
    const data = await res.json();
    return NextResponse.json(data);
  }

  const searchParams = request.nextUrl.searchParams;
  const query = new URLSearchParams();
  for (const [key, value] of searchParams.entries()) {
    query.set(key, value);
  }
  const res = await fetch(
    `${BACKEND_API_URL}/api/sboms/${sbomId}/${action}?${query}`,
    { cache: "no-store" }
  );
  const data = await res.json();
  return NextResponse.json(data);
}
