"use client";

import { useI18n } from "./LanguageProvider";

/** Renders a translated string by key. Usable inside server components as a
 *  client child, so pages stay static/SSR while text localises on the client. */
export default function T({ k }: { k: string }) {
  const { t } = useI18n();
  return <>{t(k)}</>;
}
