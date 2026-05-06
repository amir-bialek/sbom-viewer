import { NextResponse } from "next/server";

const BACKEND_API_URL = process.env.BACKEND_API_URL || "http://backend:8000";

export async function GET() {
  const res = await fetch(`${BACKEND_API_URL}/api/sboms`, {
    cache: "no-store",
  });
  const data = await res.json();
  return NextResponse.json(data);
}
