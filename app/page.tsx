import type { Metadata } from "next";
import { EvidenceConsole } from "./evidence-console";

export const metadata: Metadata = {
  title: "Overview",
  description: "Continuous PCI DSS evidence operations.",
};

export default async function Home({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const query = await searchParams;
  return <EvidenceConsole initialView={typeof query?.view === "string" ? query.view : "Overview"} />;
}
