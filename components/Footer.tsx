import Link from "next/link";
import { brand } from "@/lib/brand";

export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <span className="brand-mark" aria-hidden="true">
            ◈
          </span>
          <span className="brand-name">{brand.name}</span>
          <p>{brand.tagline}</p>
        </div>
        <div className="footer-cols">
          <div className="footer-col">
            <span className="footer-h">Product</span>
            <a href="/#scan">Scanner</a>
            <a href="/#how">How it works</a>
            <a href="/#pricing">Pricing</a>
            <Link href="/docs">API</Link>
            <a href="/#faq">FAQ</a>
          </div>
          <div className="footer-col">
            <span className="footer-h">Legal</span>
            <Link href="/privacy">Privacy Policy</Link>
            <Link href="/terms">Terms of Service</Link>
          </div>
          <div className="footer-col">
            <span className="footer-h">Contact</span>
            <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a>
          </div>
        </div>
      </div>
      <div className="footer-base">
        <span>
          © {new Date().getFullYear()} {brand.name}. Non-invasive scanning of public HTTP data.
        </span>
        <span className="footer-note">Made for a safer web.</span>
      </div>
    </footer>
  );
}
