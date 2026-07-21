"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

export default function CookieConsent() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    try {
      if (!localStorage.getItem("bastion:consent")) setShow(true);
    } catch {
      /* noop */
    }
  }, []);

  function decide(value: "accepted" | "rejected") {
    try {
      localStorage.setItem("bastion:consent", value);
    } catch {
      /* noop */
    }
    setShow(false);
  }

  if (!show) return null;

  return (
    <div className="consent" role="dialog" aria-label="Cookie consent">
      <div className="consent-inner">
        <p>
          We use only essential storage to run the scanner and remember your preferences. We don&apos;t
          use advertising or third-party tracking cookies. See our{" "}
          <Link href="/privacy">Privacy Policy</Link>.
        </p>
        <div className="consent-actions">
          <button className="consent-reject" onClick={() => decide("rejected")}>
            Essential only
          </button>
          <button className="consent-accept" onClick={() => decide("accepted")}>
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
