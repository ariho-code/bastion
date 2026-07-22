"use client";

import { useI18n } from "./LanguageProvider";
import { LANGS, type Lang } from "@/lib/i18n";
import Icon from "./Icon";

export default function LangSwitcher() {
  const { lang, setLang } = useI18n();
  return (
    <label className="lang-switch" aria-label="Select language">
      <Icon name="globe" size={15} />
      <select value={lang} onChange={(e) => setLang(e.target.value as Lang)}>
        {LANGS.map((l) => (
          <option key={l.code} value={l.code}>
            {l.label}
          </option>
        ))}
      </select>
    </label>
  );
}
