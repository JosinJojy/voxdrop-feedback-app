import Navbar from "@/components/custom/Navbar";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Voxdrop Feedback",
  description: "An Anonymous Feedback service",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className="dark:bg-neutral-950 bg-gray-100 scroll-smooth">
      <Navbar/>
      {children}
    </div>
  );
}
