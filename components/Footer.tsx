import Link from "next/link";
import { brand } from "@/lib/brand";
import { TOOLS } from "@/lib/tools";
import T from "@/components/T";
import Logo from "@/components/Logo";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <Logo size={30} variant="stacked" />
          <p>
            <T k="footer.tagline" />
          </p>
        </div>
        <div className="footer-cols">
          <div className="footer-col">
            <span className="footer-h">
              <T k="footer.product" />
            </span>
            <a href="/#scan">Scanner</a>
            <Link href="/scam-check">Scam check</Link>
            <Link href="/advanced">Advanced</Link>
            <Link href="/enterprise">Enterprise</Link>
            <a href="/#pricing">
              <T k="nav.pricing" />
            </a>
            <Link href="/docs">API</Link>
            <Link href="/developers">Developers</Link>
            <a href="/#faq">FAQ</a>
          </div>
          <div className="footer-col">
            <span className="footer-h">
              <T k="footer.tools" />
            </span>
            <Link href="/tools">
              <T k="footer.allTools" />
            </Link>
            {TOOLS.slice(0, 5).map((t) => (
              <Link key={t.slug} href={`/tools/${t.slug}`}>
                {t.name}
              </Link>
            ))}
          </div>
          <div className="footer-col">
            <span className="footer-h">
              <T k="footer.legal" />
            </span>
            <Link href="/privacy">Privacy Policy</Link>
            <Link href="/terms">Terms of Service</Link>
          </div>
          <div className="footer-col">
            <span className="footer-h">
              <T k="footer.contact" />
            </span>
            <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a>
          </div>
        </div>
      </div>
      <div className="footer-base">
        <span>
          © {new Date().getFullYear()} {brand.name}. <T k="footer.base" />
        </span>
        <span className="footer-note">
          <T k="footer.note" />
        </span>
      </div>
    </footer>
  );
}
