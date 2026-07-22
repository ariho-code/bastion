export type Lang = "en" | "es" | "fr" | "de" | "pt";

export const LANGS: { code: Lang; label: string }[] = [
  { code: "en", label: "English" },
  { code: "es", label: "Español" },
  { code: "fr", label: "Français" },
  { code: "de", label: "Deutsch" },
  { code: "pt", label: "Português" },
];

export const DEFAULT_LANG: Lang = "en";

export function normalizeLang(input?: string | null): Lang {
  const s = (input || "").slice(0, 2).toLowerCase();
  return LANGS.find((l) => l.code === s)?.code ?? DEFAULT_LANG;
}

export type Dict = Record<string, string>;

const en: Dict = {
  "nav.how": "How it works",
  "nav.pricing": "Pricing",
  "nav.api": "API",
  "nav.faq": "FAQ",
  "nav.scan": "Scan a site",
  "hero.badge": "Trusted, non-invasive security scanning",
  "hero.title1": "Is your website",
  "hero.accent": "actually secure?",
  "hero.title2": "Find out in seconds.",
  "hero.sub":
    "Bastion grades any site A–F across TLS, security headers, DNS and cookies — then hands you the exact fixes. Free, instant, and safe to run on any website you own.",
  "hero.trust1": "28 deep security checks",
  "hero.trust2": "No login required",
  "hero.trust3": "Fixes for every issue",
  "scan.placeholder": "Enter a website, e.g. yourcompany.com",
  "scan.button": "Scan now",
  "scan.tryOne": "Try one:",
  "scan.recent": "Recent",
  "how.eyebrow": "How it works",
  "how.title": "From URL to fixed in three steps",
  "feat.eyebrow": "What we check",
  "feat.title": "A complete picture of your security posture",
  "feat.sub":
    "Most tools stop at a couple of headers. Bastion looks across six categories that actually determine whether your site can be attacked.",
  "plat.eyebrow": "The platform",
  "plat.title": "Not just a scan — a security workflow",
  "plat.sub":
    "From a one-off check to continuous, automated protection across your whole portfolio — with reports your clients will actually read.",
  "price.eyebrow": "Pricing",
  "price.title": "Fair pricing that scales with you",
  "price.sub":
    "Start free forever — no account, no card. Upgrade only when you need monitoring or scale.",
  "faq.eyebrow": "FAQ",
  "faq.title": "Questions, answered",
  "final.title": "Scan your site now — it's free",
  "final.sub": "See your grade in seconds and get the fixes to reach an A.",
  "final.btn": "Run a free scan",
  "footer.tagline": "Website security, graded in seconds.",
  "footer.product": "Product",
  "footer.tools": "Free tools",
  "footer.legal": "Legal",
  "footer.contact": "Contact",
  "footer.allTools": "All tools",
  "footer.base": "Non-invasive scanning of public HTTP data.",
  "footer.note": "Made for a safer web.",
};

const es: Dict = {
  "nav.how": "Cómo funciona",
  "nav.pricing": "Precios",
  "nav.api": "API",
  "nav.faq": "Preguntas",
  "nav.scan": "Analizar sitio",
  "hero.badge": "Análisis de seguridad fiable y no invasivo",
  "hero.title1": "¿Tu sitio web es",
  "hero.accent": "realmente seguro?",
  "hero.title2": "Descúbrelo en segundos.",
  "hero.sub":
    "Bastion califica cualquier sitio de la A a la F en TLS, cabeceras de seguridad, DNS y cookies, y te da las soluciones exactas. Gratis, instantáneo y seguro en cualquier web que sea tuya.",
  "hero.trust1": "28 comprobaciones de seguridad",
  "hero.trust2": "Sin registro",
  "hero.trust3": "Soluciones para cada problema",
  "scan.placeholder": "Introduce una web, p. ej. tuempresa.com",
  "scan.button": "Analizar",
  "scan.tryOne": "Prueba una:",
  "scan.recent": "Recientes",
  "how.eyebrow": "Cómo funciona",
  "how.title": "De la URL a la solución en tres pasos",
  "feat.eyebrow": "Qué comprobamos",
  "feat.title": "Una imagen completa de tu seguridad",
  "feat.sub":
    "La mayoría de herramientas se quedan en un par de cabeceras. Bastion analiza seis categorías que determinan de verdad si tu sitio puede ser atacado.",
  "plat.eyebrow": "La plataforma",
  "plat.title": "No solo un análisis: un flujo de seguridad",
  "plat.sub":
    "Desde una comprobación puntual hasta protección continua y automática de toda tu cartera, con informes que tus clientes sí leerán.",
  "price.eyebrow": "Precios",
  "price.title": "Precios justos que crecen contigo",
  "price.sub":
    "Empieza gratis para siempre, sin cuenta ni tarjeta. Mejora solo cuando necesites monitorización o escala.",
  "faq.eyebrow": "Preguntas",
  "faq.title": "Preguntas frecuentes",
  "final.title": "Analiza tu sitio ahora — es gratis",
  "final.sub": "Consulta tu nota en segundos y obtén las soluciones para llegar a una A.",
  "final.btn": "Análisis gratuito",
  "footer.tagline": "Seguridad web, calificada en segundos.",
  "footer.product": "Producto",
  "footer.tools": "Herramientas gratis",
  "footer.legal": "Legal",
  "footer.contact": "Contacto",
  "footer.allTools": "Todas las herramientas",
  "footer.base": "Análisis no invasivo de datos HTTP públicos.",
  "footer.note": "Por una web más segura.",
};

const fr: Dict = {
  "nav.how": "Comment ça marche",
  "nav.pricing": "Tarifs",
  "nav.api": "API",
  "nav.faq": "FAQ",
  "nav.scan": "Analyser un site",
  "hero.badge": "Analyse de sécurité fiable et non intrusive",
  "hero.title1": "Votre site est-il",
  "hero.accent": "vraiment sécurisé ?",
  "hero.title2": "Découvrez-le en quelques secondes.",
  "hero.sub":
    "Bastion note n'importe quel site de A à F sur le TLS, les en-têtes de sécurité, le DNS et les cookies, puis vous donne les correctifs exacts. Gratuit, instantané et sûr sur tout site qui vous appartient.",
  "hero.trust1": "28 contrôles de sécurité",
  "hero.trust2": "Sans inscription",
  "hero.trust3": "Un correctif pour chaque problème",
  "scan.placeholder": "Entrez un site, ex. votreentreprise.com",
  "scan.button": "Analyser",
  "scan.tryOne": "Essayez :",
  "scan.recent": "Récents",
  "how.eyebrow": "Comment ça marche",
  "how.title": "De l'URL au correctif en trois étapes",
  "feat.eyebrow": "Ce que nous vérifions",
  "feat.title": "Une vue complète de votre sécurité",
  "feat.sub":
    "La plupart des outils s'arrêtent à quelques en-têtes. Bastion examine six catégories qui déterminent vraiment si votre site peut être attaqué.",
  "plat.eyebrow": "La plateforme",
  "plat.title": "Pas qu'une analyse — un flux de sécurité",
  "plat.sub":
    "D'un simple contrôle à une protection continue et automatisée de tout votre portefeuille, avec des rapports que vos clients liront vraiment.",
  "price.eyebrow": "Tarifs",
  "price.title": "Des tarifs justes qui évoluent avec vous",
  "price.sub":
    "Commencez gratuitement, sans compte ni carte. Passez à l'offre supérieure seulement pour la surveillance ou l'échelle.",
  "faq.eyebrow": "FAQ",
  "faq.title": "Vos questions, nos réponses",
  "final.title": "Analysez votre site — c'est gratuit",
  "final.sub": "Obtenez votre note en quelques secondes et les correctifs pour atteindre un A.",
  "final.btn": "Lancer une analyse gratuite",
  "footer.tagline": "La sécurité web, notée en quelques secondes.",
  "footer.product": "Produit",
  "footer.tools": "Outils gratuits",
  "footer.legal": "Légal",
  "footer.contact": "Contact",
  "footer.allTools": "Tous les outils",
  "footer.base": "Analyse non intrusive de données HTTP publiques.",
  "footer.note": "Pour un web plus sûr.",
};

const de: Dict = {
  "nav.how": "So funktioniert's",
  "nav.pricing": "Preise",
  "nav.api": "API",
  "nav.faq": "FAQ",
  "nav.scan": "Website prüfen",
  "hero.badge": "Vertrauenswürdige, nicht-invasive Sicherheitsprüfung",
  "hero.title1": "Ist deine Website",
  "hero.accent": "wirklich sicher?",
  "hero.title2": "Finde es in Sekunden heraus.",
  "hero.sub":
    "Bastion bewertet jede Website von A–F bei TLS, Sicherheits-Headern, DNS und Cookies — und liefert die genauen Lösungen. Kostenlos, sofort und sicher für jede eigene Website.",
  "hero.trust1": "28 Sicherheitsprüfungen",
  "hero.trust2": "Keine Anmeldung nötig",
  "hero.trust3": "Lösung für jedes Problem",
  "scan.placeholder": "Website eingeben, z. B. deinefirma.com",
  "scan.button": "Prüfen",
  "scan.tryOne": "Probier eine:",
  "scan.recent": "Zuletzt",
  "how.eyebrow": "So funktioniert's",
  "how.title": "Von der URL zur Lösung in drei Schritten",
  "feat.eyebrow": "Was wir prüfen",
  "feat.title": "Ein vollständiges Bild deiner Sicherheit",
  "feat.sub":
    "Die meisten Tools hören bei ein paar Headern auf. Bastion prüft sechs Kategorien, die wirklich entscheiden, ob deine Website angreifbar ist.",
  "plat.eyebrow": "Die Plattform",
  "plat.title": "Nicht nur ein Scan — ein Sicherheits-Workflow",
  "plat.sub":
    "Von der einmaligen Prüfung bis zum kontinuierlichen, automatischen Schutz deines gesamten Portfolios — mit Berichten, die deine Kunden wirklich lesen.",
  "price.eyebrow": "Preise",
  "price.title": "Faire Preise, die mit dir wachsen",
  "price.sub":
    "Für immer kostenlos starten — kein Konto, keine Karte. Upgrade nur bei Bedarf an Monitoring oder Skalierung.",
  "faq.eyebrow": "FAQ",
  "faq.title": "Fragen, beantwortet",
  "final.title": "Prüfe deine Website jetzt — kostenlos",
  "final.sub": "Sieh deine Note in Sekunden und erhalte die Lösungen für ein A.",
  "final.btn": "Kostenlos prüfen",
  "footer.tagline": "Website-Sicherheit, in Sekunden bewertet.",
  "footer.product": "Produkt",
  "footer.tools": "Kostenlose Tools",
  "footer.legal": "Rechtliches",
  "footer.contact": "Kontakt",
  "footer.allTools": "Alle Tools",
  "footer.base": "Nicht-invasive Prüfung öffentlicher HTTP-Daten.",
  "footer.note": "Für ein sichereres Web.",
};

const pt: Dict = {
  "nav.how": "Como funciona",
  "nav.pricing": "Preços",
  "nav.api": "API",
  "nav.faq": "FAQ",
  "nav.scan": "Analisar site",
  "hero.badge": "Análise de segurança confiável e não invasiva",
  "hero.title1": "O seu site é",
  "hero.accent": "realmente seguro?",
  "hero.title2": "Descubra em segundos.",
  "hero.sub":
    "O Bastion avalia qualquer site de A a F em TLS, cabeçalhos de segurança, DNS e cookies — e entrega as correções exatas. Grátis, instantâneo e seguro em qualquer site seu.",
  "hero.trust1": "28 verificações de segurança",
  "hero.trust2": "Sem cadastro",
  "hero.trust3": "Correção para cada problema",
  "scan.placeholder": "Digite um site, ex. suaempresa.com",
  "scan.button": "Analisar",
  "scan.tryOne": "Experimente:",
  "scan.recent": "Recentes",
  "how.eyebrow": "Como funciona",
  "how.title": "Da URL à correção em três passos",
  "feat.eyebrow": "O que verificamos",
  "feat.title": "Uma visão completa da sua segurança",
  "feat.sub":
    "A maioria das ferramentas para em alguns cabeçalhos. O Bastion analisa seis categorias que realmente determinam se o seu site pode ser atacado.",
  "plat.eyebrow": "A plataforma",
  "plat.title": "Não é só um scan — é um fluxo de segurança",
  "plat.sub":
    "De uma verificação pontual à proteção contínua e automática de todo o seu portfólio — com relatórios que os seus clientes vão realmente ler.",
  "price.eyebrow": "Preços",
  "price.title": "Preços justos que crescem com você",
  "price.sub":
    "Comece grátis para sempre — sem conta, sem cartão. Faça upgrade só quando precisar de monitoramento ou escala.",
  "faq.eyebrow": "FAQ",
  "faq.title": "Perguntas respondidas",
  "final.title": "Analise seu site agora — é grátis",
  "final.sub": "Veja sua nota em segundos e receba as correções para chegar a um A.",
  "final.btn": "Fazer análise grátis",
  "footer.tagline": "Segurança de sites, avaliada em segundos.",
  "footer.product": "Produto",
  "footer.tools": "Ferramentas grátis",
  "footer.legal": "Jurídico",
  "footer.contact": "Contato",
  "footer.allTools": "Todas as ferramentas",
  "footer.base": "Análise não invasiva de dados HTTP públicos.",
  "footer.note": "Por uma web mais segura.",
};

export const DICT: Record<Lang, Dict> = { en, es, fr, de, pt };

export function translate(lang: Lang, key: string): string {
  return DICT[lang]?.[key] ?? en[key] ?? key;
}
