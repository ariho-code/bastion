export type Status = "pass" | "warn" | "fail" | "info";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "transport" | "headers" | "dns" | "cookies" | "disclosure";

export interface Finding {
  id: string;
  category: Category;
  title: string;
  status: Status;
  points: number;
  maxPoints: number; // 0 => informational, excluded from scoring
  severity: Severity;
  detail: string;
  fix?: string;
  reference?: string;
  evidence?: string;
}

export interface CategoryScore {
  category: Category;
  label: string;
  score: number; // 0–100
  earned: number;
  max: number;
  pass: number;
  warn: number;
  fail: number;
}

export interface TlsInfo {
  protocol?: string;
  cipher?: string;
  authorized?: boolean;
  authorizationError?: string;
  issuer?: string;
  subjectCN?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  san?: string[];
  keyBits?: number;
}

export interface DnsInfo {
  ip?: string;
  hasMx: boolean;
  spf?: string | null;
  dmarc?: string | null;
  caa: boolean;
}

export interface ScanResult {
  url: string;
  host: string;
  domain: string;
  finalUrl: string;
  grade: string;
  score: number;
  categories: CategoryScore[];
  findings: Finding[];
  meta: {
    server?: string;
    poweredBy?: string;
    ip?: string;
    tls?: TlsInfo;
    email?: { spf: boolean; dmarc: string | null; mx: boolean };
    redirectedToHttps?: boolean;
  };
  passed: number;
  warnings: number;
  failed: number;
  scannedAt: string;
  durationMs: number;
}

export const CATEGORY_LABELS: Record<Category, string> = {
  transport: "Transport & TLS",
  headers: "Response Headers",
  dns: "DNS & Email",
  cookies: "Cookies",
  disclosure: "Info Disclosure",
};
