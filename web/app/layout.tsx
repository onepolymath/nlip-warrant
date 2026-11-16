import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";

import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono-jb", display: "swap" });

export const metadata: Metadata = {
  title: "NLIP-Warrant · attenuable, revocable delegation for NLIP agents",
  description:
    "Signed, narrowable, expiring and revocable delegation warrants enforced at NLIP (ECMA-430) agent boundaries, with a tamper-evident audit log. SafeOSE '27 AI Security Hackathon.",
  openGraph: {
    title: "NLIP-Warrant",
    description: "Authority that only shrinks as it crosses AI agents. Built on NLIP (ECMA-430).",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${mono.variable}`}>
      <body className="min-h-screen font-sans text-slate-300 antialiased">{children}</body>
    </html>
  );
}
