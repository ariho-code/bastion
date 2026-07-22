"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { brand } from "@/lib/brand";
import T from "@/components/T";
import LangSwitcher from "@/components/LangSwitcher";
import Logo from "@/components/Logo";

export default function Nav() {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  // Lock body scroll while the mobile menu is open, and close it on Escape.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open]);

  return (
    <header className="nav">
      <div className="nav-inner">
        <Link href="/" className="brand" aria-label={`${brand.name} home`} onClick={close}>
          <Logo size={26} />
        </Link>

        {/* Desktop navigation */}
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

        {/* Mobile hamburger */}
        <button
          type="button"
          className="nav-toggle"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          aria-controls="nav-mobile"
          onClick={() => setOpen((o) => !o)}
        >
          <span className={`nav-burger ${open ? "open" : ""}`} />
        </button>
      </div>

      {/* Mobile drawer */}
      <div id="nav-mobile" className={`nav-mobile ${open ? "open" : ""}`}>
        <a href="/#how" onClick={close}>
          <T k="nav.how" />
        </a>
        <a href="/#pricing" onClick={close}>
          <T k="nav.pricing" />
        </a>
        <Link href="/developers" onClick={close}>
          <T k="nav.api" />
        </Link>
        <Link href="/advanced" onClick={close}>
          Advanced
        </Link>
        <a href="/#faq" onClick={close}>
          <T k="nav.faq" />
        </a>
        <div className="nav-mobile-row">
          <LangSwitcher />
        </div>
        <a href="/#scan" className="nav-cta nav-mobile-cta" onClick={close}>
          <T k="nav.scan" />
        </a>
      </div>
    </header>
  );
}
