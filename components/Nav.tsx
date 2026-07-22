import Link from "next/link";
import { brand } from "@/lib/brand";
import T from "@/components/T";
import LangSwitcher from "@/components/LangSwitcher";
import Logo from "@/components/Logo";

export default function Nav() {
  return (
    <header className="nav">
      <div className="nav-inner">
        <Link href="/" className="brand" aria-label={`${brand.name} home`}>
          <Logo size={26} />
        </Link>
        <nav className="nav-links">
          <a href="/#how">
            <T k="nav.how" />
          </a>
          <a href="/#pricing">
            <T k="nav.pricing" />
          </a>
          <Link href="/developers">
            <T k="nav.api" />
          </Link>
          <Link href="/advanced">Advanced</Link>
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
