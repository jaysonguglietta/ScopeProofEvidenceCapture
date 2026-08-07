import type { Metadata } from "next";
import { EvidenceConsole } from "./evidence-console";

export const metadata: Metadata = {
  title: "Overview",
  description: "Continuous PCI DSS evidence operations.",
};

export default function Home() {
  return <EvidenceConsole />;
}
