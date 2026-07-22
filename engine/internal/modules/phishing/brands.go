package phishing

// This file is the module's threat-intelligence knowledge base: the brands most
// commonly impersonated by phishing and crypto-scam sites, the affix words that
// combine with a brand name to form a fake domain, the high-abuse TLDs, lexical
// scam-domain tokens, high-risk hosting fingerprints, and the content
// fingerprints of credential/wallet harvesting. It is intentionally data-only
// and dependency-free so it can grow without touching detection logic.

// brand describes a frequently-impersonated organization. tokens are the
// lowercase strings a fake domain embeds (e.g. "paypal"); domains are the
// legitimate registrable domains that must NEVER be treated as impersonation.
type brand struct {
	name    string
	tokens  []string
	domains []string
}

// brands covers the targets that account for the overwhelming majority of
// phishing worldwide, plus the crypto and African mobile-money brands that
// ordinary people are most often scammed through — the gap generic tools miss.
var brands = []brand{
	// --- Crypto exchanges & wallets (drainer / seed-phrase phishing) ---
	{"Binance", []string{"binance"}, []string{"binance.com", "binance.us"}},
	{"Coinbase", []string{"coinbase"}, []string{"coinbase.com"}},
	{"MetaMask", []string{"metamask"}, []string{"metamask.io"}},
	{"Trust Wallet", []string{"trustwallet"}, []string{"trustwallet.com"}},
	{"Ledger", []string{"ledger"}, []string{"ledger.com"}},
	{"Trezor", []string{"trezor"}, []string{"trezor.io"}},
	{"Kraken", []string{"kraken"}, []string{"kraken.com"}},
	{"Blockchain.com", []string{"blockchain"}, []string{"blockchain.com"}},
	{"Phantom", []string{"phantom"}, []string{"phantom.app"}},
	{"Exodus", []string{"exodus"}, []string{"exodus.com"}},
	{"Crypto.com", []string{"crypto"}, []string{"crypto.com"}},
	{"OKX", []string{"okx"}, []string{"okx.com"}},
	{"Bybit", []string{"bybit"}, []string{"bybit.com"}},
	{"Uniswap", []string{"uniswap"}, []string{"uniswap.org"}},
	{"OpenSea", []string{"opensea"}, []string{"opensea.io"}},
	{"Etherscan", []string{"etherscan"}, []string{"etherscan.io"}},
	{"TradingView", []string{"tradingview"}, []string{"tradingview.com"}},
	{"Robinhood", []string{"robinhood"}, []string{"robinhood.com"}},
	{"eToro", []string{"etoro"}, []string{"etoro.com"}},

	// --- Payments & banks ---
	{"PayPal", []string{"paypal"}, []string{"paypal.com"}},
	{"Stripe", []string{"stripe"}, []string{"stripe.com"}},
	{"Cash App", []string{"cashapp"}, []string{"cash.app"}},
	{"Venmo", []string{"venmo"}, []string{"venmo.com"}},
	{"Zelle", []string{"zelle"}, []string{"zellepay.com"}},
	{"Wise", []string{"wise"}, []string{"wise.com"}},
	{"Revolut", []string{"revolut"}, []string{"revolut.com"}},
	{"Chase", []string{"chase"}, []string{"chase.com"}},
	{"Wells Fargo", []string{"wellsfargo"}, []string{"wellsfargo.com"}},
	{"Bank of America", []string{"bankofamerica"}, []string{"bankofamerica.com"}},
	{"Barclays", []string{"barclays"}, []string{"barclays.co.uk", "barclays.com"}},
	{"HSBC", []string{"hsbc"}, []string{"hsbc.com", "hsbc.co.uk"}},

	// --- Big tech / accounts (credential phishing) ---
	{"Microsoft", []string{"microsoft", "office365"}, []string{"microsoft.com", "office.com", "outlook.com", "live.com"}},
	{"Apple", []string{"apple", "icloud"}, []string{"apple.com", "icloud.com"}},
	{"Google", []string{"google", "gmail"}, []string{"google.com", "gmail.com"}},
	{"Amazon", []string{"amazon"}, []string{"amazon.com"}},
	{"Netflix", []string{"netflix"}, []string{"netflix.com"}},
	{"Facebook", []string{"facebook"}, []string{"facebook.com", "fb.com", "meta.com"}},
	{"Instagram", []string{"instagram"}, []string{"instagram.com"}},
	{"WhatsApp", []string{"whatsapp"}, []string{"whatsapp.com"}},
	{"LinkedIn", []string{"linkedin"}, []string{"linkedin.com"}},
	{"Dropbox", []string{"dropbox"}, []string{"dropbox.com"}},
	{"X / Twitter", []string{"twitter"}, []string{"twitter.com", "x.com"}},
	{"TikTok", []string{"tiktok"}, []string{"tiktok.com"}},
	{"Telegram", []string{"telegram"}, []string{"telegram.org", "telegram.me", "t.me"}},

	// --- Africa: mobile money, fintech & telecom (highly targeted, under-served) ---
	{"M-Pesa / Safaricom", []string{"mpesa", "safaricom"}, []string{"safaricom.co.ke", "vodacom.co.tz"}},
	{"MTN MoMo", []string{"mtnmomo"}, []string{"mtn.com", "mtn.co.ug", "mtn.ng"}},
	{"Airtel Money", []string{"airtelmoney"}, []string{"airtel.com", "airtel.africa"}},
	{"Flutterwave", []string{"flutterwave"}, []string{"flutterwave.com"}},
	{"Paystack", []string{"paystack"}, []string{"paystack.com"}},
	{"OPay", []string{"opay"}, []string{"opayweb.com"}},
	{"Chipper Cash", []string{"chipper"}, []string{"chippercash.com"}},
	{"SportyBet", []string{"sportybet"}, []string{"sportybet.com"}},

	// --- Delivery & government (fee / package scams) ---
	{"DHL", []string{"dhl"}, []string{"dhl.com"}},
	{"FedEx", []string{"fedex"}, []string{"fedex.com"}},
	{"UPS", []string{"ups"}, []string{"ups.com"}},
	{"USPS", []string{"usps"}, []string{"usps.com"}},
	{"IRS", []string{"irs"}, []string{"irs.gov"}},
}

// affixes are the words scammers concatenate onto a brand to build a plausible
// domain — "paypal-secure", "verifyapple", "mtn-account". Matching a brand token
// next to one of these is a strong combosquatting signal.
var affixes = []string{
	"login", "signin", "secure", "security", "verify", "verified", "verification",
	"account", "accounts", "update", "confirm", "support", "service", "services",
	"help", "helpdesk", "wallet", "team", "official", "online", "app", "web",
	"portal", "auth", "recovery", "alert", "center", "centre", "customer", "care",
	"access", "unlock", "live", "my", "get", "real", "safe", "vault", "connect",
	"reward", "rewards", "claim", "gift", "bonus", "pay", "id", "ai", "hub",
	"earn", "profit", "trade", "bot", "invest", "trading", "finance", "capital",
}

// abuseTLDs are top-level domains disproportionately used for abuse — mostly
// free or ultra-cheap registrations. Presence is a soft signal, meaningful only
// alongside other indicators.
var abuseTLDs = map[string]bool{
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true, "top": true,
	"xyz": true, "buzz": true, "click": true, "link": true, "country": true,
	"kim": true, "work": true, "support": true, "rest": true, "fit": true,
	"zip": true, "mov": true, "cam": true, "quest": true, "cfd": true,
	"sbs": true, "autos": true, "bond": true, "lol": true, "icu": true,
	"cyou": true, "shop": true, "online": true, "site": true, "website": true,
	"space": true, "fun": true, "live": true, "pro": true, "info": true,
	"club": true, "pw": true, "cc": true, "ws": true, "biz": true,
}

// seedPhraseMarkers are phrases that only ever appear on wallet-draining scam
// pages. No legitimate service asks a user to type a recovery/seed phrase into a
// website — so any hit here is treated as unambiguously malicious.
var seedPhraseMarkers = []string{
	"seed phrase", "recovery phrase", "secret phrase", "mnemonic phrase",
	"12-word phrase", "24-word phrase", "12 word phrase", "24 word phrase",
	"enter your private key", "wallet private key", "import your wallet",
	"restore your wallet", "keystore file", "keystore json",
	"validate your wallet", "sync your wallet", "your recovery phrase",
	"paste your seed", "enter seed phrase", "backup phrase",
	"secret recovery phrase", "reveal seed phrase",
}

// walletDrainerMarkers indicate a dApp-style "connect wallet" flow. These are
// normal on legitimate DeFi, so they only count when corroborated by an
// impersonation or other risk signal (see assess()).
var walletDrainerMarkers = []string{
	"connect wallet", "walletconnect", "connect your wallet", "claim airdrop",
	"claim your airdrop", "claim reward", "activate wallet", "rectify wallet",
	"wallet verification", "migrate your wallet", "approve transaction",
	"sign the transaction", "enable ethereum", "web3auth",
}

// scamDomainTokens are SLD fragments that appear in throwaway investment,
// AI-trading, and crypto-scam domains even when no famous brand is impersonated.
// Matching is word/boundary aware so "hub" alone does not fire on "github".
var scamDomainTokens = []string{
	"aihub", "ai-hub", "aiprofit", "aitrade", "aitrading", "aibot", "aiinvest",
	"cryptoearn", "cryptohub", "cryptotrade", "cryptobot", "cryptoinvest",
	"forexbot", "forextrade", "forexsignal", "tradebot", "tradingbot",
	"investpro", "investhub", "earnhub", "earnpro", "profitmax", "profitbot",
	"bitcoingive", "btcgiveaway", "walletfix", "walletverify", "walletsync",
	"claimnow", "airdroplive", "airdrophub", "tokenclaim", "coindrop",
	"doubler", "multiplier", "getrich", "quickprofit", "dailyprofit",
	"binaryopt", "binarytrade", "fxsignal", "copytrade", "autotrade",
	"miningcloud", "cloudminer", "hashpower", "nftmint", "nftclaim",
	"futureai", "future-ai", "smartinvest", "wealthbot", "cashbot",
	"elon", "musk", "teslagive", "spacexgive",
}

// scamDomainParts are weaker single tokens that only count when the SLD also
// contains a second commercial/urgency word (corroboration required).
var scamDomainParts = []string{
	"ai", "hub", "earn", "profit", "invest", "trading", "trade", "forex",
	"crypto", "bitcoin", "btc", "eth", "nft", "defi", "token", "coin",
	"bonus", "reward", "airdrop", "claim", "wallet", "vault", "capital",
	"finance", "wealth", "rich", "money", "cash", "fund", "yield",
	"future", "smart", "auto", "bot", "signal", "broker", "exchange",
}

// highRiskHosting marks ASNs / org fingerprints frequently used by disposable
// scam infrastructure (bulletproof / abuse-tolerant providers). Soft alone;
// strong when the domain is also young or lexical-scam.
var highRiskHosting = []string{
	"ddos-guard", "ddosguard", "as57724",
	"quasi networks", "quasi-networks",
	"//c/ispsystem", "ispsystem",
	"hostkey", "serverius", "retn",
	"m247", "blazingfast", "psychz",
	"choopa", "constant", // vultr residual naming sometimes
	"bulletproof", "abuser",
}

// keywordCluster is one scam-genre fingerprint applied to page text.
//
// Design rule: never fire on a single common word. Either require minAny hits
// from `any`, or require every phrase in `all` (optionally plus one from `any`).
type keywordCluster struct {
	name   string
	label  string
	all    []string // every phrase must be present
	any    []string // candidates; need minAny hits (default 2)
	minAny int      // 0 => default 2 when any is non-empty and all is empty
	weight int      // 0 => default 10
}

var scamKeywordClusters = []keywordCluster{
	{"crypto-giveaway", "fake crypto giveaway / airdrop", nil, []string{
		"double your", "send 0.1", "send 1 btc", "send btc", "free bitcoin",
		"free crypto", "elon musk", "10x your", "10,000 usdt", "10000 usdt",
		"crypto giveaway", "bitcoin giveaway", " eth giveaway", "claim airdrop",
		"multiply your crypto", "return on investment crypto",
	}, 1, 14},
	{"lottery", "lottery / prize scam", nil, []string{
		"you have won", "you've won", "lucky winner", "claim your prize",
		"congratulations you", "you are a winner", "million dollars prize",
		"selected as winner", "unclaimed prize",
	}, 1, 14},
	{"mobile-money", "mobile-money reversal / PIN scam", nil, []string{
		"reverse the transaction", "enter your pin", "mpesa pin", "momo pin",
		"confirm your pin", "wrong number transaction", "send it back now",
		"agent withdrawal", "sim swap",
	}, 1, 14},
	{"investment", "fake investment / forex / AI-trading scheme", nil, []string{
		"guaranteed profit", "guaranteed returns", "double your money",
		"roi daily", "forex signals", "get rich quick", "profit daily",
		"ai trading bot", "ai investment", "automated trading", "copy trading",
		"binary options", "up to 300%", "passive income daily",
		"licensed broker", "minimum deposit", "account manager will",
		"risk free investment", "guaranteed income",
	}, 2, 12},
	{"account-suspended", "account-suspension phishing", nil, []string{
		"account has been suspended", "account is suspended", "unusual activity",
		"verify your identity", "reactivate your account", "confirm your identity",
		"your account will be closed", "unauthorized login",
		"limited access to your account", "secure your account now",
	}, 1, 12},
	{"urgency-payment", "urgency / advance-fee pressure", nil, []string{
		"act now or", "within 24 hours", "account will be locked",
		"pay the fee", "release fee", "customs fee", "clearance fee",
		"processing fee required", "wire the funds", "gift card payment",
	}, 2, 10},
	{"romance-pig", "romance / pig-butchering lure", nil, []string{
		"//trading platform i use", "my broker", "investment platform",
		"send me usdt", "crypto platform he", "she told me to invest",
	}, 1, 12},
}
