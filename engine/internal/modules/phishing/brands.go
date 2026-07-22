package phishing

// This file is the module's threat-intelligence knowledge base: the brands most
// commonly impersonated by phishing and crypto-scam sites, the affix words that
// combine with a brand name to form a fake domain, the high-abuse TLDs, and the
// content fingerprints of credential/wallet harvesting. It is intentionally
// data-only and dependency-free so it can grow without touching detection logic.

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
	{"Microsoft", []string{"microsoft"}, []string{"microsoft.com", "office.com", "outlook.com", "live.com"}},
	{"Apple", []string{"apple", "icloud"}, []string{"apple.com", "icloud.com"}},
	{"Google", []string{"google", "gmail"}, []string{"google.com", "gmail.com"}},
	{"Amazon", []string{"amazon"}, []string{"amazon.com"}},
	{"Netflix", []string{"netflix"}, []string{"netflix.com"}},
	{"Facebook", []string{"facebook"}, []string{"facebook.com"}},
	{"Instagram", []string{"instagram"}, []string{"instagram.com"}},
	{"WhatsApp", []string{"whatsapp"}, []string{"whatsapp.com"}},
	{"LinkedIn", []string{"linkedin"}, []string{"linkedin.com"}},
	{"Dropbox", []string{"dropbox"}, []string{"dropbox.com"}},

	// --- Africa: mobile money, fintech & telecom (highly targeted, under-served) ---
	{"M-Pesa / Safaricom", []string{"mpesa", "safaricom"}, []string{"safaricom.co.ke", "vodacom.co.tz"}},
	{"MTN MoMo", []string{"mtnmomo", "mtn"}, []string{"mtn.com", "mtn.co.ug", "mtn.ng"}},
	{"Airtel Money", []string{"airtelmoney", "airtel"}, []string{"airtel.com", "airtel.africa"}},
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
	"reward", "rewards", "claim", "gift", "bonus", "pay", "id",
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
}

// seedPhraseMarkers are phrases that only ever appear on wallet-draining scam
// pages. No legitimate service asks a user to type a recovery/seed phrase into a
// website — so any hit here is treated as unambiguously malicious.
var seedPhraseMarkers = []string{
	"seed phrase", "recovery phrase", "secret phrase", "mnemonic phrase",
	"12-word phrase", "24-word phrase", "12 word phrase", "24 word phrase",
	"enter your private key", "wallet private key", "import your wallet",
	"restore your wallet", "keystore file", "keystore json", "wallet password",
	"validate your wallet", "sync your wallet", "your recovery phrase",
}

// walletDrainerMarkers indicate a dApp-style "connect wallet" flow. These are
// normal on legitimate DeFi, so they only count when corroborated by an
// impersonation or other risk signal (see assess()).
var walletDrainerMarkers = []string{
	"connect wallet", "walletconnect", "connect your wallet", "claim airdrop",
	"claim your airdrop", "claim reward", "activate wallet", "rectify wallet",
	"wallet verification", "migrate your wallet",
}

// scamKeywordClusters are groups of words whose co-occurrence characterizes a
// specific scam genre. They add supporting weight and, crucially, a plain-English
// explanation of *what kind* of scam the user may be looking at.
var scamKeywordClusters = []struct {
	name  string
	label string
	all   []string // every phrase must be present
	any   []string // OR: at least one must be present (empty => ignored)
}{
	{"crypto-giveaway", "fake crypto giveaway / airdrop", []string{}, []string{
		"double your", "send 0.1", "send 1 btc", "giveaway", "airdrop", "free bitcoin",
		"free crypto", "elon musk", "10x your", "10,000 usdt",
	}},
	{"lottery", "lottery / prize scam", []string{}, []string{
		"you have won", "you've won", "lucky winner", "claim your prize",
		"congratulations you", "you are a winner", "million dollars",
	}},
	{"mobile-money", "mobile-money reversal / PIN scam", []string{}, []string{
		"reverse the transaction", "enter your pin", "mpesa pin", "momo pin",
		"confirm your pin", "wrong number transaction", "send it back",
	}},
	{"investment", "fake investment / forex scheme", []string{}, []string{
		"guaranteed profit", "guaranteed returns", "double your money",
		"roi daily", "forex signals", "get rich", "investment plan", "profit daily",
	}},
	{"account-suspended", "account-suspension phishing", []string{}, []string{
		"account has been suspended", "account is suspended", "unusual activity",
		"verify your identity", "reactivate your account", "confirm your identity",
		"your account will be closed", "unauthorized login",
	}},
}
