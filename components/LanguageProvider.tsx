"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { type Lang, DEFAULT_LANG, normalizeLang, translate } from "@/lib/i18n";

interface Ctx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (k: string) => string;
}

const LanguageContext = createContext<Ctx>({
  lang: DEFAULT_LANG,
  setLang: () => {},
  t: (k) => k,
});

export function useI18n() {
  return useContext(LanguageContext);
}

export default function LanguageProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(DEFAULT_LANG);

  // Detect from storage / browser on mount.
  useEffect(() => {
    let initial: Lang = DEFAULT_LANG;
    try {
      const stored = localStorage.getItem("bastion:lang");
      initial = normalizeLang(stored || navigator.language);
    } catch {
      /* noop */
    }
    setLangState(initial);
  }, []);

  useEffect(() => {
    try {
      document.documentElement.lang = lang;
    } catch {
      /* noop */
    }
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("bastion:lang", l);
    } catch {
      /* noop */
    }
  }, []);

  const t = useCallback((k: string) => translate(lang, k), [lang]);

  return (
    <LanguageContext.Provider value={{ lang, setLang, t }}>{children}</LanguageContext.Provider>
  );
}
