import type { MetadataRoute } from "next";
import { brand } from "@/lib/brand";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: `${brand.name} — Website Security Scanner`,
    short_name: brand.shortName,
    description: brand.shortDescription,
    start_url: "/",
    display: "standalone",
    background_color: "#0a0e14",
    theme_color: "#0a0e14",
    icons: [
      { src: "/icon.svg", sizes: "any", type: "image/svg+xml" },
      { src: "/brand/icon?size=192", sizes: "192x192", type: "image/png" },
      { src: "/brand/icon?size=512", sizes: "512x512", type: "image/png" },
    ],
  };
}
