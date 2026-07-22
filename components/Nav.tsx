import Link from "next/link";
import { brand } from "@/lib/brand";

export default function Nav() {
  return (
    <header className="nav">
      <div className="nav-inner">
        <Link href="/" className="brand" aria-label={`${brand.name} home`}>
          <span className="brand-mark" aria-hidden="true">
            ◈
          </span>
          <span className="brand-name">{brand.name}</span>
        </Link>
        <nav className="nav-links">
          <a href="/#how">How it works</a>
          <a href="/#pricing">Pricing</a>
          <Link href="/docs">API</Link>
          <a href="/#faq">FAQ</a>
          <a href="/#scan" className="nav-cta">
            Scan a site
          </a>
        </nav>
      </div>
    </header>
  );
}
