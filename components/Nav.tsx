import Link from "next/link";
import { brand } from "@/lib/brand";
import T from "@/components/T";
import LangSwitcher from "@/components/LangSwitcher";

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
          <a href="/#how">
            <T k="nav.how" />
          </a>
          <a href="/#pricing">
            <T k="nav.pricing" />
          </a>
          <Link href="/docs">
            <T k="nav.api" />
          </Link>
          <a href="/#faq">
            <T k="nav.faq" />
          </a>
          <LangSwitcher />
          <a href="/#scan" className="nav-cta">
            <T k="nav.scan" />
          </a>
        </nav>
      </div>
    </header>
  );
}
