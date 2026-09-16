const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json"
    }
  });
}

function getRisk(score) {
  const finalScore = Math.max(0, Math.min(100, Math.round(score)));

  let level = "LOWER RISK";

  if (finalScore >= 70) {
    level = "HIGH RISK";
  } else if (finalScore >= 40) {
    level = "MEDIUM RISK";
  }

  return {
    score: finalScore,
    level
  };
}

async function checkPhishTank(url) {
  try {
    const form = new URLSearchParams();
    form.set("url", url);
    form.set("format", "json");

    const result = await fetch(
      "http://checkurl.phishtank.com/checkurl/",
      {
        method: "POST",
        headers: {
          "User-Agent": "FraudShield/3.0",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: form.toString()
      }
    );

    const raw = await result.text();

    if (!result.ok) {
      return {
        found: false,
        available: false,
        status: result.status,
        diagnostic: raw.slice(0, 300)
      };
    }

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      return {
        found: false,
        available: false,
        status: result.status,
        diagnostic: raw.slice(0, 300)
      };
    }

    const item = data && data.results ? data.results : {};

    return {
      found:
        item.in_database === true &&
        item.valid === true,
      available: true,
      status: result.status
    };
  } catch (error) {
    return {
      found: false,
      available: false,
      error: String(error)
    };
  }
}
function detectLookalikeBrand(hostname) {
  const brandPatterns = {
    paypal: [
      "paypal.com"
    ],
    facebook: [
      "facebook.com",
      "facebook.net"
    ],
    instagram: [
      "instagram.com"
    ],
    whatsapp: [
      "whatsapp.com"
    ],
    telegram: [
      "telegram.org"
    ],
    microsoft: [
      "microsoft.com",
      "live.com",
      "office.com",
      "microsoftonline.com"
    ],
    google: [
      "google.com"
    ],
    apple: [
      "apple.com",
      "icloud.com"
    ],
    amazon: [
      "amazon.com"
    ],
    binance: [
      "binance.com"
    ]
  };

  const normalizedHostname =
    hostname
      .toLowerCase()
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/5/g, "s")
      .replace(/7/g, "t");

  for (const [brand, officialDomains] of Object.entries(brandPatterns)) {
    const resemblesBrand =
      normalizedHostname.includes(brand);

    const isOfficial =
      officialDomains.some(
        domain =>
          hostname === domain ||
          hostname.endsWith("." + domain)
      );

    if (resemblesBrand && !isOfficial) {
      return {
        detected: true,
        brand
      };
    }
  }

  return {
    detected: false,
    brand: null
  };
}
function analyzeUrlIntelligence(url) {
  let score = 0;
  const signals = [];

  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();
  const search = url.search.toLowerCase();
  const fullUrl = url.href.toLowerCase();

  // Redirect parameters can hide the real destination.
  const redirectParameters = [
    "url=",
    "redirect=",
    "redirect_url=",
    "redirect_uri=",
    "return=",
    "return_url=",
    "next=",
    "continue=",
    "target=",
    "dest=",
    "destination="
  ];

  const hasRedirectParameter =
    redirectParameters.some(
      parameter => search.includes(parameter)
    );

  if (hasRedirectParameter) {
    score += 15;

    signals.push(
      "The URL contains a redirect parameter that may send the user to another destination."
    );
  }

  // Sensitive information placed inside URL parameters.
  const sensitiveParameters = [
    "password=",
    "passwd=",
    "pass=",
    "otp=",
    "pin=",
    "cvv=",
    "token=",
    "secret=",
    "apikey=",
    "api_key="
  ];

  const hasSensitiveParameter =
    sensitiveParameters.some(
      parameter => search.includes(parameter)
    );

  if (hasSensitiveParameter) {
    score += 25;

    signals.push(
      "The URL contains a parameter that appears to reference sensitive credentials or security information."
    );
  }

  // Multiple query parameters can sometimes indicate tracking,
  // redirection, or obfuscation. This is only a weak signal.
  const queryParameterCount =
    search
      ? search.slice(1).split("&").filter(Boolean).length
      : 0;

  if (queryParameterCount >= 6) {
    score += 10;

    signals.push(
      "The URL contains an unusually large number of query parameters."
    );
  }

  // Excessive path depth.
  const pathParts =
    pathname
      .split("/")
      .filter(Boolean);

  if (pathParts.length >= 6) {
    score += 10;

    signals.push(
      "The URL contains an unusually deep path structure."
    );
  }

  // Suspicious double-slash path pattern.
  if (
    pathname.includes("//")
  ) {
    score += 10;

    signals.push(
      "The URL contains an unusual double-slash path pattern."
    );
  }

  // Common executable/download file patterns.
  const suspiciousFileExtensions = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".msi",
    ".apk",
    ".zip"
  ];

  if (
    suspiciousFileExtensions.some(
      extension => pathname.endsWith(extension)
    )
  ) {
    score += 20;

    signals.push(
      "The URL points to a file type that can potentially deliver executable or compressed content."
    );
  }

  // Very long query strings can be used for obfuscation.
  if (search.length > 200) {
    score += 10;

    signals.push(
      "The URL contains an unusually long query string."
    );
  }

  // Obfuscated hexadecimal or encoded-looking URL content.
  const encodedParameterCount =
    (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length;

  if (encodedParameterCount >= 4) {
    score += 10;

    signals.push(
      "The URL contains multiple encoded characters that may make its destination harder to inspect."
    );
  }

  return {
    score,
    signals
  };
}
async function analyzeWebsite(input) {
  let url;

  try {
    url = new URL(input.trim());
  } catch {
    return {
      type: "website",
      ...getRisk(25),
      signals: [
        "The supplied website address is not a valid URL."
      ],
      advice:
        "Check the website address carefully before visiting it."
    };
  }

  let score = 0;
  const signals = [];

  const hostname = url.hostname.toLowerCase();
  const fullUrl = url.href.toLowerCase();
  const lookalikeBrand =
  detectLookalikeBrand(hostname);
  const urlIntelligence =
  analyzeUrlIntelligence(url);

score += urlIntelligence.score;

signals.push(
  ...urlIntelligence.signals
);

if (lookalikeBrand.detected) {
  score += 40;

  signals.push(
    "The domain appears to imitate the " +
    lookalikeBrand.brand +
    " brand using a lookalike spelling."
  );
}

  const knownMaliciousDomains = [
    "qujqmtk.com"
  ];

  const knownMalicious = knownMaliciousDomains.some(
    domain =>
      hostname === domain ||
      hostname.endsWith("." + domain)
  );

  if (knownMalicious) {
    score += 80;

    signals.push(
      "This domain is on FraudShield's known malicious-domain list."
    );
  }

  const officialBrandDomains = {
    paypal: ["paypal.com"],
    facebook: ["facebook.com", "facebook.net"],
    instagram: ["instagram.com"],
    whatsapp: ["whatsapp.com"],
    telegram: ["telegram.org"],
    microsoft: [
      "microsoft.com",
      "live.com",
      "office.com",
      "microsoftonline.com"
    ],
    google: ["google.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com"],
    binance: ["binance.com"]
  };

  const hostnameLabels = hostname.split(".");

  const suspiciousBrandMatch = Object.entries(
    officialBrandDomains
  ).some(([brand, officialDomains]) => {
    const brandInHostname = hostnameLabels.some(
      label => label.includes(brand)
    );

    const isOfficial = officialDomains.some(
      domain =>
        hostname === domain ||
        hostname.endsWith("." + domain)
    );

    return brandInHostname && !isOfficial;
  });

  if (suspiciousBrandMatch) {
    score += 25;

    signals.push(
      "The hostname contains a major brand name but is not on FraudShield's official-domain allowlist."
    );
  }

  if (url.protocol !== "https:") {
    score += 20;

    signals.push(
      "The website does not use HTTPS."
    );
  }

  const ipAddressPattern =
    /^\d{1,3}(\.\d{1,3}){3}$/;

  if (ipAddressPattern.test(hostname)) {
    score += 30;

    signals.push(
      "The website uses an IP address instead of a normal domain name."
    );
  }

  if (hostname.includes("xn--")) {
    score += 25;

    signals.push(
      "The domain uses punycode, which can sometimes be used in deceptive lookalike domains."
    );
  }

  const hyphenCount =
    (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    score += 10;

    signals.push(
      "The domain contains an unusually high number of hyphens."
    );
  }

  if (hostname.length > 50) {
    score += 10;

    signals.push(
      "The hostname is unusually long."
    );
  }

  if (fullUrl.includes("@")) {
    score += 25;

    signals.push(
      "The URL contains an @ symbol, which can be used to disguise the actual destination."
    );
  }

  const suspiciousWords = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "security", 
    "update",
    "confirm",
    "password",
    "wallet",
    "bonus",
    "reward",
    "claim",
    "free",
    "urgent"
  ];

  const matchedWords = suspiciousWords.filter(
    word => fullUrl.includes(word)
  );

  if (matchedWords.length >= 2) {
    score += 20;

    signals.push(
      "The URL contains multiple words commonly associated with deceptive or phishing pages."
    );
  }

  const sensitiveWords = [
    "login",
    "password",
    "wallet",
    "account",
    "bank"
  ];

  if (
    sensitiveWords.some(
      word => fullUrl.includes(word)
    ) &&
    matchedWords.length >= 1
  ) {
    score += 15;

    signals.push(
      "The URL appears to target sensitive account or financial information."
    );
  }

  const hostnameParts = hostname.split(".");

  if (hostnameParts.length >= 4) {
    score += 10;

    signals.push(
      "The hostname contains many subdomain levels."
    );
  }

  if (fullUrl.length > 120) {
    score += 10;

    signals.push(
      "The URL is unusually long."
    );
  }

  if (/%[0-9a-f]{2}/i.test(fullUrl)) {
    score += 5;

    signals.push(
      "The URL contains percent-encoded characters."
    );
  }

  const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
  ];

  if (
    shorteners.some(
      domain => hostname === domain
    )
  ) {
    score += 15;

    signals.push(
      "The URL uses a link-shortening service."
    );
  }

  const suspiciousDomainPatterns = [
    "login-",
    "verify-",
    "secure-",
    "account-",
    "update-",
    "confirm-",
    "-login",
    "-verify",
    "-secure",
    "-account",
    "-update",
    "-confirm"
  ];

  if (
    suspiciousDomainPatterns.some(
      pattern => hostname.includes(pattern)
    )
  ) {
    score += 20;

    signals.push(
      "The domain uses a suspicious login, verification, security, or account pattern."
    );
  }

  const phishTank =
    await checkPhishTank(url.href);

  if (phishTank.available === false) {
    signals.push(
      "External phishing intelligence was unavailable. This result is based on FraudShield's own analysis."
    );
  }

  if (phishTank.found) {
    score += 50;

    signals.push(
      "External phishing intelligence identified this URL as a phishing site."
    );
  }

  const risk = getRisk(score);

  return {
    type: "website",
    ...risk,
    signals,
    advice:
      risk.score >= 70
        ? "Do not enter passwords, banking information, recovery codes, or payment details on this website."
        : risk.score >= 40
        ? "Proceed carefully and verify the website through an official source before entering sensitive information."
        : "No major warning signs were detected by the current FraudShield checks, but always verify important websites independently."
  };
}
function analyzeEmailIntelligence(input) {
  const text = String(input || "").trim();
  const lower = text.toLowerCase();

  let score = 0;
  const signals = [];


  // Look for sender/from addresses.
  const senderMatch =
    text.match(
      /(?:from|sender)\s*:\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i
    );

  const sender =
    senderMatch
      ? senderMatch[1].toLowerCase()
      : null;


  // Common free/disposable email providers.
  const freeEmailDomains = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "proton.me",
    "protonmail.com"
  ];

  if (
    sender &&
    freeEmailDomains.some(
      domain => sender.endsWith("@" + domain)
    )
  ) {
    score += 5;

    signals.push(
      "The sender uses a common free email provider. This is not proof of fraud, but verify the sender independently."
    );
  }

  // Suspicious sender/domain patterns.
  const suspiciousEmailPatterns = [
    "support-",
    "security-",
    "verify-",
    "account-",
    "admin-",
    "billing-",
    "payment-",
    "helpdesk-",
    "login-"
  ];

  if (
    sender &&
    suspiciousEmailPatterns.some(
      pattern => sender.includes(pattern)
    )
  ) {
    score += 15;

    signals.push(
      "The sender address uses a pattern commonly associated with impersonation or account-security messages."
    );
  }

  // Brand impersonation in email addresses.
  const emailBrands = [
    "paypal",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "binance"
  ];

  const officialEmailDomains = {
    paypal: ["paypal.com"],
    facebook: ["facebook.com", "facebook.net"],
    instagram: ["instagram.com"],
    whatsapp: ["whatsapp.com"],
    telegram: ["telegram.org"],
    microsoft: [
      "microsoft.com",
      "live.com",
      "office.com",
      "microsoftonline.com"
    ],
    google: ["google.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com"],
    binance: ["binance.com"]
  };

  if (sender) {
    const senderDomain =
      sender.split("@")[1] || "";

    for (const brand of emailBrands) {
      if (
        sender.includes(brand) &&
        !officialEmailDomains[brand].some(
          domain =>
            senderDomain === domain ||
            senderDomain.endsWith("." + domain)
        )
      ) {
        score += 30;

        signals.push(
          "The sender address appears to use the " +
          brand +
          " brand but is not from an official " +
          brand +
          " domain."
        );

        break;
      }
    }
  }

  // Lookalike spelling in sender domains.
  if (sender) {
    const senderDomain =
      sender.split("@")[1] || "";

    const normalizedDomain =
      senderDomain
        .replace(/0/g, "o")
        .replace(/1/g, "l")
        .replace(/3/g, "e")
        .replace(/5/g, "s")
        .replace(/7/g, "t");

    for (const brand of emailBrands) {
      if (
        normalizedDomain.includes(brand) &&
        !officialEmailDomains[brand].some(
          domain =>
            senderDomain === domain ||
            senderDomain.endsWith("." + domain)
        )
      ) {
        score += 30;

        signals.push(
          "The sender domain appears to imitate the " +
          brand +
          " brand using a lookalike spelling."
        );

        break;
      }
    }
  }

  // Reply-To address mismatch.
  const replyToMatch =
    text.match(
      /reply-to\s*:\s*([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i
    );

  if (sender && replyToMatch) {
    const replyTo =
      replyToMatch[1].toLowerCase();

    const senderDomain =
      sender.split("@")[1] || "";

    const replyDomain =
      replyTo.split("@")[1] || "";

    if (
      senderDomain &&
      replyDomain &&
      senderDomain !== replyDomain
    ) {
      score += 25;

      signals.push(
        "The sender and Reply-To addresses use different domains."
      );
    }
  }

  // Suspicious email links.
  const hasLink =
    /https?:\/\/|www\./i.test(text);

  if (hasLink) {
    score += 10;

    signals.push(
      "The email contains a web link."
    );
  }

  // Strong social-engineering combinations.
  

  // Urgency, money and credential risks are handled
// by analyzeMessage() so they are not double-counted.

  return {
    score,
    signals
  };
}
async function analyzeMessage(input) {
  const text = input.trim().toLowerCase();

  let score = 0;
  const signals = [];

  const urgency = [
    "urgent",
    "immediately",
    "right now",
    "act now",
    "as soon as possible",
    "hurry",
    "quickly"
  ];

  const money = [
    "send money",
    "send me",
    "transfer",
    "payment",
    "fee",
    "bank",
    "bitcoin",
    "crypto",
    "investment",
    "wallet",
    "deposit",
    "cash",
    "funds",
    "₦",
    "naira"
  ];

  const credentials = [
    "password",
    "passcode",
    "otp",
    "one time password",
    "verification code",
    "pin",
    "cvv",
    "login"
  ];

  const prizes = [
    "you won",
    "winner",
    "congratulations",
    "prize",
    "lottery",
    "free gift",
    "claim your"
  ];

  const threats = [
    "account will be closed",
    "account suspended",
    "police",
    "arrest",
    "legal action",
    "your account will be blocked"
  ];

  const impersonation = [
    "i am your boss",
    "i'm your boss",
    "this is your boss",
    "i am the ceo",
    "i'm the ceo",
    "this is the ceo",
    "i am your pastor",
    "i'm your pastor",
    "this is your pastor",
    "customer support",
    "support team"
  ];

  const secrecy = [
    "keep this secret",
    "keep it secret",
    "don't tell anyone",
    "do not tell anyone",
    "keep this between us",
    "tell nobody",
    "don't share this"
  ];

  const hasUrgency =
    urgency.some(word => text.includes(word));

  const hasMoney =
    money.some(word => text.includes(word));

  const hasCredentials =
    credentials.some(word => text.includes(word));

  const hasPrize =
    prizes.some(word => text.includes(word));

  const hasLink =
    /https?:\/\/|www\./i.test(text);

  const hasThreat =
    threats.some(word => text.includes(word));

  const hasImpersonation =
    impersonation.some(word =>
      text.includes(word)
    );

  const hasSecrecy =
    secrecy.some(word => text.includes(word));

  if (hasUrgency) {
    score += 20;

    signals.push(
      "The message uses urgency or pressure."
    );
  }

  if (hasMoney) {
    score += 20;

    signals.push(
      "The message involves money, payment, transfer, or financial assets."
    );
  }

  if (hasCredentials) {
    score += 25;

    signals.push(
      "The message requests or mentions sensitive credentials or verification codes."
    );
  }

  if (hasPrize) {
    score += 15;

    signals.push(
      "The message contains prize, lottery, reward, or unexpected-win language."
    );
  }

  if (hasLink) {
    score += 15;

    signals.push(
      "The message contains a web link."
    );
  }

  if (hasThreat) {
    score += 20;

    signals.push(
      "The message uses threats or consequences to pressure the recipient."
    );
  }

  if (hasImpersonation) {
    score += 15;

    signals.push(
      "The message may be impersonating an authority, company, support team, or known person."
    );
  }

  if (hasMoney && hasCredentials) {
    score += 20;

    signals.push(
      "The message combines a financial request with sensitive account information."
    );
  }

  if (hasUrgency && hasMoney) {
    score += 20;

    signals.push(
      "Urgency is combined with a financial request."
    );
  }

  if (hasUrgency && hasCredentials) {
    score += 20;

    signals.push(
      "Urgency is combined with a request involving credentials or codes."
    );
  }

  if (hasPrize && hasMoney) {
    score += 15;

    signals.push(
      "The message combines a prize or reward with financial activity."
    );
  }

  if (
    hasUrgency &&
    hasMoney &&
    /stranded|stolen|accident|hospital|emergency|sick|crisis/i.test(text)
  ) {
    score += 25;

    signals.push(
      "The message uses an emergency or personal crisis to request financial help."
    );
  }

  if (
    /double your money|guaranteed profit|guaranteed return|risk free investment|100% profit/i.test(text)
  ) {
    score += 25;

    signals.push(
      "The message makes an unusually strong investment or profit promise."
    );
  }

  if (
    /job|employment|vacancy|work from home/i.test(text) &&
    hasMoney
  ) {
    score += 25;

    signals.push(
      "The message may involve a job scam requesting money or payment."
    );
  }

  if (hasSecrecy) {
    score += 15;

    signals.push(
      "The sender pressures the recipient to keep the communication secret."
    );
  }

  if (hasPrize && hasLink) {
    score += 20;

    signals.push(
      "A prize or reward claim is combined with a web link."
    );
  }

  if (
    /investment|profit|return|crypto|bitcoin/i.test(text) &&
    hasLink
  ) {
    score += 20;

    signals.push(
      "Investment or cryptocurrency language is combined with a link."
    );
  }

  const risk = getRisk(score);

  return {
    type: "message",
    ...risk,
    signals,
    advice:
      risk.score >= 70
        ? "Do not send money, passwords, OTPs, PINs, or other sensitive information. Verify the sender through an independent channel."
        : risk.score >= 40
        ? "Be cautious. Verify the sender and any request independently before taking action."
        : "No major warning signs were detected by the current message checks."
  };
}

async function analyzePhone(input, env) {
  const original = String(input || "").trim();

  const numberOnly =
    original.replace(/\D/g, "");

  let score = 0;
  const signals = [];

  if (!numberOnly) {
    return {
      type: "phone",
      ...getRisk(30),
      signals: [
        "No valid phone number was supplied."
      ],
      advice:
        "Enter a complete phone number."
    };
  }

  let localValid = false;
  let internationalValid = false;

  if (
    numberOnly.length === 11 &&
    numberOnly.startsWith("0")
  ) {
    localValid = true;
  }

  if (
    numberOnly.length >= 10 &&
    numberOnly.length <= 15 &&
    numberOnly.startsWith("234")
  ) {
    internationalValid = true;
  }

  if (
    !localValid &&
    !internationalValid
  ) {
    score += 30;

    signals.push(
      "The number does not match a normal Nigerian local or international format."
    );
  }

  if (localValid) {
    signals.push(
      "The number matches a Nigerian local phone-number format."
    );
  }

  if (internationalValid) {
    signals.push(
      "The number matches an international Nigerian +234 format."
    );
  }

  if (
    localValid &&
    (
      numberOnly.startsWith("0909") ||
      numberOnly.startsWith("0919")
    )
  ) {
    score += 10;

    signals.push(
      "The number uses a prefix currently treated as requiring extra caution by FraudShield."
    );
  }

  if (/^(\d)\1+$/.test(numberOnly)) {
    score += 15;

    signals.push(
      "The phone number contains repeated digits."
    );
  }

  const ipqsNumber =
    localValid
      ? "+234" + numberOnly.slice(1)
      : internationalValid
      ? "+" + numberOnly
      : original;


const ipqsKey =
  env && env.IPQS_API_KEY
    ? String(env.IPQS_API_KEY).trim()
    : "";

if (!ipqsKey) {
  // No IPQS key available.
} else {
  try {
      const ipqsUrl =
  "https://www.ipqualityscore.com/api/json/phone" +
  "?key=" +
  encodeURIComponent(ipqsKey) +
  "&phone=" +
  encodeURIComponent(ipqsNumber) +
  "&country=NG";

const ipqsResponse = await fetch(
  ipqsUrl,
  {
    method: "GET",
    headers: {
      "Accept": "application/json"
    }
  }
);

      const raw =
        await ipqsResponse.text();

      let data = null;

      try {
        data = JSON.parse(raw);
      } catch {
        data = null;
      }

      if (!ipqsResponse.ok) {
        let errorMessage =
          "IPQS HTTP status: " +
          ipqsResponse.status +
          ".";

        if (data && data.message) {
          errorMessage +=
            " Message: " +
            String(data.message);
        } else if (raw) {
          errorMessage +=
            " Response: " +
            raw.slice(0, 250);
        }

        signals.push(
          "IPQS request failed. " +
          errorMessage
        );
      } else if (!data) {
        signals.push(
          "IPQS returned a successful HTTP response, but the response was not valid JSON."
        );
      } else if (data.success === false) {
        let errorMessage =
          data.message ||
          "Unknown IPQS API error.";

        if (
          Array.isArray(data.errors) &&
          data.errors.length > 0
        ) {
          errorMessage +=
            " Details: " +
            data.errors.join("; ");
        }

        signals.push(
          "IPQS could not complete the reputation check: " +
          errorMessage
        );
      } else {
        const fraudScore =
          Number(data.fraud_score || 0);

        if (fraudScore >= 90) {
          score += 60;

          signals.push(
            "IPQS reports a very high phone fraud score."
          );
        } else if (fraudScore >= 85) {
          score += 50;

          signals.push(
            "IPQS reports a high phone fraud score."
          );
        } else if (fraudScore >= 75) {
          score += 35;

          signals.push(
            "IPQS reports an elevated phone fraud score."
          );
        }

        if (data.recent_abuse === true) {
          score += 25;

          signals.push(
            "IPQS reports recent abuse associated with this number."
          );
        }

        if (data.risky === true) {
          score += 20;

          signals.push(
            "IPQS marks this phone number as risky."
          );
        }

        if (data.spammer === true) {
          score += 25;

          signals.push(
            "IPQS identifies this number as a possible spammer."
          );
        }

        if (data.active === false) {
          score += 15;

          signals.push(
            "IPQS reports that the phone line is not active."
          );
        }

        if (data.valid === false) {
          score += 20;

          signals.push(
            "IPQS reports that the phone number is not valid."
          );
        }

        if (data.VOIP === true) {
          signals.push(
            "IPQS identifies this number as a VOIP number."
          );
        }

        if (data.prepaid === true) {
          signals.push(
            "IPQS identifies this number as prepaid."
          );
        }

        if (
          data.fraud_score !== undefined
        ) {
          signals.push(
            "IPQS fraud score: " +
            fraudScore +
            "/100."
          );
        }

        if (data.carrier) {
          signals.push(
            "IPQS carrier: " +
            String(data.carrier) +
            "."
          );
        }

        if (data.line_type) {
          signals.push(
            "IPQS line type: " +
            String(data.line_type) +
            "."
          );
        }

        if (data.country) {
          signals.push(
            "IPQS country: " +
            String(data.country) +
            "."
          );
        }

        if (data.request_id) {
          signals.push(
            "IPQS request completed successfully."
          );
        }
      }
    } catch (error) {
      signals.push(
        "IPQS connection error: " +
        String(error)
      );
    }
  }

  const risk = getRisk(score);
const hasWarningSignals =
  score > 0;
  return {
    type: "phone",
    ...risk,
    signals,
    advice:
  risk.score >= 70
    ? "Treat this account as high risk. Do not send money, passwords, OTPs, PINs, recovery codes, or banking information. Verify the account through the platform's official channels."
    : risk.score >= 40
    ? "Use caution. Do not rely on profile names, badges, photos, or claims of being official. Verify the account through an independent official channel."
    : hasWarningSignals
    ? "Some caution signals were detected. Verify the account independently before trusting important claims or requests."
    : "No major warning signs were detected by the current account checks. This does not prove the account is genuine; verify important accounts independently."
  };
}

function analyzeAccount(input) {
  const text = String(input || "").trim();
  const lower = text.toLowerCase();

  let score = 0;
  const signals = [];

  if (!text) {
    return {
      type: "account",
      ...getRisk(20),
      signals: [
        "No account or profile information was supplied."
      ],
      advice:
      risk.score >= 70
        ? "Treat this account as high risk. Do not send money, passwords, OTPs, PINs, recovery codes, or banking information. Verify the account through the platform's official channels."
        : risk.score >= 40
        ? "Use caution. Do not rely on profile names, badges, photos, or claims of being official. Verify the account through an independent official channel."
        : hasWarningSignals
        ? "Some caution signals were detected. Verify the account independently before trusting important claims or requests."
        : "No major warning signs were detected by the current account checks. This does not prove the account is genuine; verify important accounts independently."
    };
  }

  // Platform detection
  const platforms = [
    "telegram",
    "whatsapp",
    "facebook",
    "instagram",
    "tiktok",
    "twitter",
    "x.com",
    "youtube",
    "linkedin"
  ];

  const detectedPlatforms = platforms.filter(
    platform => lower.includes(platform)
  );

  if (detectedPlatforms.length > 0) {
    signals.push(
      "Platform detected: " +
      detectedPlatforms.join(", ") +
      "."
    );
  }

  // Profile URL detection
  const hasProfileUrl =
    /https?:\/\/|www\./i.test(text);

  if (hasProfileUrl) {
    score += 10;

    signals.push(
      "The account information contains a profile or web address."
    );
  }

  // High-risk impersonation terms
  const impersonationTerms = [
    "official",
    "verified",
    "support",
    "customer service",
    "admin",
    "administrator",
    "manager",
    "ceo",
    "founder",
    "security",
    "helpdesk",
    "recovery",
    "agent"
  ];

  const matchedImpersonationTerms =
    impersonationTerms.filter(
      term => lower.includes(term)
    );

  if (matchedImpersonationTerms.length > 0) {
    score += 15;

    signals.push(
      "The profile uses authority, support, verification, or official-looking language."
    );
  }
  
  // Financial/investment language
  const financialTerms = [
    "investment",
    "invest",
    "profit",
    "crypto",
    "bitcoin",
    "forex",
    "trading",
    "wallet",
    "giveaway",
    "prize",
    "lottery",
    "double your money",
    "guaranteed return",
    "guaranteed profit"
  ];

  const matchedFinancialTerms =
    financialTerms.filter(
      term => lower.includes(term)
    );

  if (matchedFinancialTerms.length > 0) {
    score += 20;

    signals.push(
      "The account contains investment, cryptocurrency, giveaway, prize, or financial-promotion language."
    );
  }

  // Requests for money
  const moneyRequest =
    /send money|send me|transfer|payment|deposit|fee|cash|funds|pay now|pay immediately|bank transfer|crypto payment/i.test(
      lower
    );

  if (moneyRequest) {
    score += 25;

    signals.push(
      "The account information contains language associated with requesting money or payment."
    );
  }

    // Credential requests
  const credentialRequest =
    /password|passcode|otp|one time password|verification code|pin|cvv|recovery code|login details/i.test(
      lower
    );

  // Public-person impersonation detection
  const publicPeople = [
    "elon musk",
    "mark zuckerberg",
    "bill gates",
    "jeff bezos",
    "donald trump",
    "barack obama",
    "cristiano ronaldo",
    "lionel messi",
    "mr beast",
    "taylor swift"
  ];

  const detectedPublicPerson =
    publicPeople.find(person =>
      lower.includes(person)
    );

  if (detectedPublicPerson) {
    score += 25;

    signals.push(
      "The profile appears to use the name of a well-known public figure."
    );

    if (matchedFinancialTerms.length > 0) {
      score += 20;

      signals.push(
        "The public-figure identity is combined with investment, financial, or promotional language."
      );
    }

    if (moneyRequest) {
      score += 20;

      signals.push(
        "The public-figure identity is combined with a request for money or payment."
      );
    }

    if (credentialRequest) {
      score += 20;

      signals.push(
        "The public-figure identity is combined with a request for sensitive credentials or security codes."
      );
    }
  }

  if (credentialRequest) {
    score += 25;

    signals.push(
      "The account information requests or references sensitive credentials or security codes."
    );
  }

  // Urgency
  // Job / recruitment scam detection
const jobRecruitment =
  /job|employment|vacancy|recruitment|recruiting|hiring|career|work from home|remote position|salary|hr|human resources|registration fee|application fee|interview/i.test(
    lower
  );

if (jobRecruitment) {
  score += 20;

  signals.push(
    "The account contains job, recruitment, employment, or hiring-related language."
  );
}
// Personal information request detection
const personalInfoRequest =
  /personal information|personal details|date of birth|home address|residential address|identity document|id card|passport|bank details|bank account|account number|national id|nin|bvn/i.test(
    lower
  );

if (personalInfoRequest) {
  score += 15;

  signals.push(
    "The account requests personal or identity information that should be verified before sharing."
  );
}
if (
  jobRecruitment &&
  /no interview|required fee|registration fee|application fee|pay.*job|pay.*position|send.*fee/i.test(
    lower
  )
) {
  score += 25;

  signals.push(
    "The account may involve a job or recruitment scam requesting an unusual payment or bypassing normal hiring steps."
  );
}
  const urgency =
    /urgent|immediately|right now|act now|hurry|as soon as possible|quickly/i.test(
      lower
    );

  if (urgency) {
    score += 15;

    signals.push(
      "The account information uses urgency or pressure."
    );
  }

  // Secrecy
  const secrecy =
    /keep this secret|keep it secret|don't tell anyone|do not tell anyone|keep this between us|tell nobody|don't share this/i.test(
      lower
    );

  if (secrecy) {
    score += 20;

    signals.push(
      "The account information pressures the recipient to keep the communication secret."
    );
  }

  // Prize + money combination
  const prize =
    /giveaway|prize|lottery|winner|you won|free gift|claim your/i.test(
      lower
    );

  if (prize && moneyRequest) {
    score += 20;

    signals.push(
      "A prize or giveaway claim is combined with a financial request."
    );
  }

  // Investment + guaranteed returns
  if (
    /investment|crypto|bitcoin|forex|trading/i.test(lower) &&
    /guaranteed|risk free|double your money|100% profit/i.test(lower)
  ) {
    score += 25;

    signals.push(
      "The account makes unusually strong or guaranteed investment-profit claims."
    );
  }

  // Multiple risk combinations
  if (urgency && moneyRequest) {
    score += 20;

    signals.push(
      "Urgency is combined with a financial request."
    );
  }

  if (urgency && credentialRequest) {
    score += 20;

    signals.push(
      "Urgency is combined with a request for sensitive account information."
    );
  }

  if (moneyRequest && credentialRequest) {
    score += 20;

    signals.push(
      "The account combines a financial request with sensitive credentials."
    );
  }

  // Username-like suspicious patterns
const usernameMatch =
  text.match(
    /@([a-z0-9._-]{4,100})/i
  );

const username =
  usernameMatch
    ? usernameMatch[1].toLowerCase()
    : "";

const suspiciousUsername =
  /(official|support|admin|security|ceo|verified|manager|helpdesk|recovery)/i.test(
    username
  );

if (suspiciousUsername) {
  score += 10;

  signals.push(
    "The username or account identifier resembles an authority or support account."
  );
}

// Very long username/profile identifiers
if (
  username &&
  username.length > 30
) {
  score += 10;

  signals.push(
    "The account identifier is unusually long."
  );
}

  const risk = getRisk(score);

const uniqueSignals = [
  ...new Set(signals)
];

const hasWarningSignals =
  score > 0;

return {
  type: "account",
  ...risk,
  signals: uniqueSignals,
    advice:
      risk.score >= 70
        ? "Treat this account as high risk. Do not send money, passwords, OTPs, PINs, recovery codes, or banking information. Verify the account through the platform's official channels."
        : risk.score >= 40
        ? "Use caution. Do not rely on profile names, badges, photos, or claims of being official. Verify the account through an independent official channel."
        : "No major warning signs were detected by the current account checks. This does not prove the account is genuine; verify important accounts independently."
  };
}
function analyzeRelationship(input) {
  const text = String(input || "").trim();
  const lower = text.toLowerCase();

  let score = 0;
  const signals = [];
  const connections = [];

  // -----------------------------
  // Extract phone numbers
  // -----------------------------
  const phones = text.match(
    /(?:\+234|0)\d[\d\s().-]{8,14}\d/g
  ) || [];

  if (phones.length > 0) {
    connections.push(
      ...phones.map(phone => ({
        type: "phone",
        value: phone.trim()
      }))
    );
  }

  // -----------------------------
  // Extract email addresses
  // -----------------------------
  const emails = text.match(
    /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi
  ) || [];

  if (emails.length > 0) {
    connections.push(
      ...emails.map(email => ({
        type: "email",
        value: email.toLowerCase()
      }))
    );
  }

  // -----------------------------
  // Extract URLs
  // -----------------------------
  const urls = text.match(
    /https?:\/\/[^\s]+|www\.[^\s]+/gi
  ) || [];

  if (urls.length > 0) {
    connections.push(
      ...urls.map(url => ({
        type: "website",
        value: url.replace(/[),.!?]+$/, "")
      }))
    );
  }

  // -----------------------------
  // Extract usernames
  // -----------------------------
  const usernames = text.match(
  /(?<![\w.])@[a-z0-9._-]{4,100}/gi
) || [];

  if (usernames.length > 0) {
    connections.push(
      ...usernames.map(username => ({
        type: "account",
        value: username.toLowerCase()
      }))
    );
  }

  // -----------------------------
  // Detect platforms
  // -----------------------------
  const platforms = [
    "telegram",
    "whatsapp",
    "facebook",
    "instagram",
    "tiktok",
    "twitter",
    "x.com",
    "youtube",
    "linkedin"
  ];

  const detectedPlatforms = platforms.filter(
    platform => lower.includes(platform)
  );

  // -----------------------------
  // Relationship strength
  // -----------------------------

  if (phones.length > 0 && emails.length > 0) {
    score += 15;

    signals.push(
      "The submitted information connects a phone number with an email address."
    );
  }

  if (emails.length > 0 && urls.length > 0) {
    score += 15;

    signals.push(
      "The submitted information connects an email address with a website or URL."
    );
  }

  if (usernames.length > 0 && phones.length > 0) {
    score += 15;

    signals.push(
      "The submitted information connects a social account identifier with a phone number."
    );
  }

  if (usernames.length > 0 && emails.length > 0) {
    score += 15;

    signals.push(
      "The submitted information connects a social account identifier with an email address."
    );
  }

  if (usernames.length > 0 && urls.length > 0) {
    score += 15;

    signals.push(
      "The submitted information connects a social account identifier with a website or URL."
    );
  }

  if (phones.length > 0 && urls.length > 0) {
    score += 10;

    signals.push(
      "The submitted information connects a phone number with a website or URL."
    );
  }

  // -----------------------------
  // Multiple identities
  // -----------------------------

  if (connections.length >= 3) {
    score += 10;

    signals.push(
      "Multiple identity indicators were supplied for relationship analysis."
    );
  }

  if (connections.length >= 4) {
    score += 10;

    signals.push(
      "The information forms a broader identity relationship across multiple data types."
    );
  }

  // -----------------------------
  // Suspicious relationship patterns
  // -----------------------------

  if (
    /official|support|security|admin|verified|manager|helpdesk|recovery/i.test(
      lower
    )
  ) {
    score += 10;

    signals.push(
      "The relationship contains authority, support, security, or official-looking language."
    );
  }

  if (
    /investment|crypto|bitcoin|forex|trading|profit|giveaway|prize/i.test(
      lower
    )
  ) {
    score += 15;

    signals.push(
      "The relationship contains financial, investment, cryptocurrency, giveaway, or prize language."
    );
  }

  if (
    /send money|send me|transfer|payment|deposit|fee|bank transfer|pay now/i.test(
      lower
    )
  ) {
    score += 20;

    signals.push(
      "The relationship contains a request for money or payment."
    );
  }

  if (
    /password|otp|verification code|passcode|pin|cvv|recovery code/i.test(
      lower
    )
  ) {
    score += 20;

    signals.push(
      "The relationship contains sensitive credential or security-code language."
    );
  }

  // -----------------------------
  // Platform information
  // -----------------------------

  if (detectedPlatforms.length > 0) {
    signals.push(
      "Platforms detected: " +
      detectedPlatforms.join(", ") +
      "."
    );
  }

  // -----------------------------
  // Remove duplicate connections
  // -----------------------------

  const uniqueConnections = [];
  const seenConnections = new Set();

  for (const connection of connections) {
    const key =
      connection.type +
      ":" +
      connection.value;

    if (!seenConnections.has(key)) {
      seenConnections.add(key);
      uniqueConnections.push(connection);
    }
  }

  // -----------------------------
  // Risk
  // -----------------------------

  const risk = getRisk(score);

  const uniqueSignals = [
    ...new Set(signals)
  ];

  return {
    type: "relationship",
    ...risk,
    connections: uniqueConnections,
    platforms: detectedPlatforms,
    signals: uniqueSignals,
    advice:
      risk.score >= 70
        ? "Treat this relationship as high risk. Verify each identity independently and do not send money, passwords, OTPs, PINs, or banking information."
        : risk.score >= 40
        ? "Use caution. Verify the connected identities independently before trusting requests or transactions."
        : "No major relationship warning signs were detected by the current checks. This does not prove the identities are genuine."
  };
}
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    if (request.method === "GET") {
      return response({
        service: "FraudShield API",
        status: "online",
        version: "3.2"
      });
    }

    if (request.method !== "POST") {
      return response(
        {
          error: "Method not allowed"
        },
        405
      );
    }

    try {
      const body =
        await request.json();

      const type =
        String(
          body.type || ""
        ).toLowerCase();

      const input =
        String(
          body.input || ""
        ).trim();

      if (!input) {
        return response(
          {
            error: "Input is required."
          },
          400
        );
      }

      let result;

      if (
        type === "website" ||
        type === "url"
      ) {
        result =
          await analyzeWebsite(input);
      } else if (type === "email") {
  const emailIntelligence =
    analyzeEmailIntelligence(input);

  const messageResult =
    await analyzeMessage(input);

  result = {
    ...messageResult,
    type: "email",
    score: getRisk(
      messageResult.score +
      emailIntelligence.score
    ).score,
    level: getRisk(
      messageResult.score +
      emailIntelligence.score
    ).level,
    signals: [
      ...emailIntelligence.signals,
      ...messageResult.signals
    ]
  };

  result.advice =
    result.score >= 70
      ? "Do not send money, passwords, OTPs, PINs, or banking information. Verify the sender through an independent channel."
      : result.score >= 40
      ? "Be cautious. Verify the sender, email domain, links, and any request independently before taking action."
      : "No major warning signs were detected by the current email checks.";
} else if (type === "message") {
  result =
    await analyzeMessage(input);
      } else if (
        type === "phone"
      ) {
        result =
          await analyzePhone(
            input,
            env
          );
      } else if (
  type === "account"
) {
  result =
    await analyzeAccount(input);
} else if (
  type === "relationship"
) {
  result =
    analyzeRelationship(input);
} else {
        return response(
          {
            error:
              "Unknown analysis type. Use website, email, message, phone, account, or relationship."
          },
          400
        );
      }

      return response(result);
    } catch (error) {
      return response(
        {
          error: "Server error.",
          message: String(error)
        },
        500
      );
    }
  }
};
