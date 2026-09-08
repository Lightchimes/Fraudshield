const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

function getRisk(score, signals) {
  score = Math.min(Math.max(score, 0), 100);

  return {
    score,
    level:
      score >= 70
        ? "HIGH RISK"
        : score >= 40
        ? "MEDIUM RISK"
        : "LOWER RISK",
    signals:
      signals.length > 0
        ? signals
        : ["No obvious scam signals were detected by the current rules."],
    advice:
      score >= 70
        ? "Do not enter passwords, OTPs, PINs, banking details, or payment information. Verify the source independently."
        : score >= 40
        ? "Be very cautious. Verify the website, sender, or account through an independent trusted source before taking action."
        : "No major warning signs were detected, but always verify before sharing sensitive information."
  };
}
 async function checkPhishTank(url) {
  try {
    const form = new URLSearchParams();

    form.append("url", url);
    form.append("format", "json");

    const response = await fetch(
      "http://checkurl.phishtank.com/checkurl/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "FraudShield/2.0"
        },
        body: form.toString()
      }
    );

    const responseText = await response.text();

    if (!response.ok) {
      return {
        found: false,
        available: false,
        status: response.status,
        diagnostic: responseText.slice(0, 300)
      };
    }
    let data;

    try {
      data = JSON.parse(responseText);
    } catch {
      return {
        found: false,
        available: false,
        status: response.status,
        diagnostic: responseText.slice(0, 300)
      };
    }

    const result = data.results;

    return {
      found:
        result?.in_database === true &&
        (
          result?.valid === true ||
          result?.valid === "y"
        ),
      available: true,
      status: response.status,
      in_database: result?.in_database ?? null,
      valid: result?.valid ?? null
    };

  } catch (error) {
    return {
      found: false,
      available: false,
      error: error.message
    };
  }
}
async function analyzeWebsite(input) {
  const text = input.trim();
  let score = 0;
  const signals = [];

  let url;

  try {
    url = new URL(text);
  } catch {
    return getRisk(25, [
      "This does not appear to be a valid website address."
    ]);
  }
const threat = await checkPhishTank(text);

if (threat.found) {
  score += 50;
  signals.push("PhishTank reports this URL as a verified phishing URL.");
} else if (!threat.available) {
  signals.push(
    "External phishing intelligence was unavailable. This result is based on FraudShield's own analysis."
  );
}
  const hostname = url.hostname.toLowerCase();
    // Known malicious domains
  const knownMaliciousDomains = [
    "qujqmtk.com"
  ];

  const knownMalicious = knownMaliciousDomains.some(
    domain =>
      hostname === domain ||
      hostname.endsWith("." + domain)
  );
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

const suspiciousBrandMatch = Object.entries(officialBrandDomains).some(
  ([brand, officialDomains]) => {
    const brandInHostname = hostnameLabels.some(label =>
      label.includes(brand)
    );

    const isOfficial = officialDomains.some(
      domain =>
        hostname === domain ||
        hostname.endsWith("." + domain)
    );

    return brandInHostname && !isOfficial;
  }
);

if (suspiciousBrandMatch) {
  score += 25;
  signals.push(
    "The hostname contains a major brand name but is not on FraudShield's official-domain allowlist."
  );
}
  if (knownMalicious) {
    score += 80;
    signals.push(
      "This domain is on FraudShield's known malicious-domain list."
    );
  }
  const full = text.toLowerCase();

  // HTTPS
  if (url.protocol !== "https:") {
    score += 20;
    signals.push("The website does not use HTTPS.");
  }

  // IP address instead of domain
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    signals.push("The link uses an IP address instead of a normal domain name.");
  }

  // Punycode
  if (hostname.includes("xn--")) {
    score += 25;
    signals.push("The domain uses punycode, which can sometimes hide look-alike characters.");
  }

  // Many hyphens
  const hyphens = (hostname.match(/-/g) || []).length;

  if (hyphens >= 3) {
    score += 10;
    signals.push("The domain contains many hyphens.");
  }

  // Very long hostname
  if (hostname.length > 50) {
    score += 10;
    signals.push("The domain name is unusually long.");
  }

  // Suspicious URL symbols
  if (text.includes("@")) {
    score += 25;
    signals.push("The URL contains an @ symbol, which can disguise the real destination.");
  }

  // Suspicious words
  const suspiciousWords = [
    "verify",
    "verification",
    "secure",
    "login",
    "account",
    "update",
    "confirm",
    "wallet",
    "claim",
    "bonus",
    "reward",
    "urgent",
    "suspended",
    "password",
    "signin",
    "unlock",
    "security",
    "payment",
    "billing",
    "invoice",
    "refund",
    "free",
    "prize"
  ];

  const found = suspiciousWords.filter(word => full.includes(word));

  if (found.length >= 2) {
    score += 20;
    signals.push(
      "The address contains several words commonly associated with deceptive or phishing links."
    );
  }

  // Suspicious combinations
  const sensitiveTargets = [
    "bank",
    "paypal",
    "wallet",
    "crypto",
    "bitcoin",
    "airdrop",
    "investment",
    "trading",
    "password",
    "otp"
  ];

  const foundTargets = sensitiveTargets.filter(word => full.includes(word));

  if (foundTargets.length >= 1 && found.length >= 1) {
    score += 15;
    signals.push(
      "The link appears to target sensitive accounts, money, credentials, or financial activity."
    );
  }

  // Excessive subdomains
  const parts = hostname.split(".");

  if (parts.length >= 4) {
    score += 10;
    signals.push("The domain uses an unusually large number of subdomains.");
  }

  // Very long URL
  if (text.length > 120) {
    score += 10;
    signals.push("The URL is unusually long.");
  }

  // Suspicious encoded characters
  if (/%[0-9a-f]{2}/i.test(text)) {
    score += 5;
    signals.push("The URL contains encoded characters that may obscure part of the destination.");
  }

  // Known URL shorteners
  const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at"
  ];

  if (shorteners.includes(hostname)) {
    score += 15;
    signals.push(
      "This is a URL-shortening service, so the final destination is hidden until the link is followed."
    );
  }
  // Suspicious domain patterns
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

  if (suspiciousDomainPatterns.some(pattern => hostname.includes(pattern))) {
    score += 20;
    signals.push(
      "The domain contains patterns commonly used by deceptive login, verification, or account-update websites."
    );
  }
  const risk = getRisk(score, signals);

return {
  ...risk,
  phishTank: threat
};
}

function analyzeMessage(input) {
  const text = input.trim();
  const lower = text.toLowerCase();

  let score = 0;
  const signals = [];

  const urgency = [
    "urgent",
    "immediately",
    "act now",
    "within 24 hours",
    "today",
    "last chance",
    "suspended",
    "expires",
    "final warning",
    "respond now",
    "right away"
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
    "pin",
    "otp",
    "verification code",
    "login",
    "signin",
    "security code",
    "one-time password",
    "passcode"
  ];

  const prizes = [
    "winner",
    "won",
    "prize",
    "bonus",
    "reward",
    "free",
    "giveaway",
    "lottery",
    "congratulations"
  ];

  const links = [
    "http://",
    "https://",
    "www.",
    "bit.ly",
    "tinyurl",
    "t.co",
    "cutt.ly"
  ];

  const threats = [
    "account will be closed",
    "account will be deleted",
    "account has been suspended",
    "account is suspended",
    "lose access",
    "blocked",
    "terminated",
    "legal action",
    "police",
    "arrest",
    "fine"
  ];

  const impersonation = [
    "customer service",
    "support team",
    "security team",
    "bank staff",
    "official representative",
    "verify your identity",
    "confirm your identity"
  ];

  const requests = [
    "send",
    "transfer",
    "click",
    "open",
    "reply",
    "call",
    "contact",
    "share",
    "provide",
    "confirm",
    "verify",
    "pay"
  ];

  const foundUrgency = urgency.filter(word => lower.includes(word));
  const foundMoney = money.filter(word => lower.includes(word));
  const foundCredentials = credentials.filter(word => lower.includes(word));
  const foundPrizes = prizes.filter(word => lower.includes(word));
  const foundLinks = links.filter(word => lower.includes(word));
  const foundThreats = threats.filter(word => lower.includes(word));
  const foundImpersonation = impersonation.filter(word =>
    lower.includes(word)
  );
  const foundRequests = requests.filter(word =>
    lower.includes(word)
  );

  if (foundUrgency.length > 0) {
    score += 20;
    signals.push(
      "The message creates urgency or pressure to act quickly."
    );
  }

  if (foundMoney.length > 0) {
    score += 20;
    signals.push(
      "The message involves money, payment, banking, investment, or transfers."
    );
  }

  if (foundCredentials.length > 0) {
    score += 25;
    signals.push(
      "The message asks for passwords, PINs, OTPs, verification codes, or other login information."
    );
  }

  if (foundPrizes.length > 0) {
    score += 15;
    signals.push(
      "The message contains prize, reward, bonus, lottery, or free-offer language."
    );
  }

  if (foundLinks.length > 0) {
    score += 15;
    signals.push(
      "The message contains a link. Verify the destination before opening it."
    );
  }

  if (foundThreats.length > 0) {
    score += 20;
    signals.push(
      "The message uses threats, account suspension, loss of access, or legal consequences to pressure the recipient."
    );
  }

  if (foundImpersonation.length > 0) {
    score += 15;
    signals.push(
      "The message may be impersonating a support, security, banking, or official representative."
    );
  }

  if (
    foundRequests.length > 0 &&
    foundCredentials.length > 0
  ) {
    score += 20;
    signals.push(
      "The message combines a request for action with sensitive security information."
    );
  }

  if (
    foundUrgency.length > 0 &&
    foundMoney.length > 0
  ) {
    score += 20;
    signals.push(
      "The message combines urgency with a financial request."
    );
  }

  if (
    foundUrgency.length > 0 &&
    foundCredentials.length > 0
  ) {
    score += 20;
    signals.push(
      "The message combines urgency with a request involving sensitive credentials."
    );
  }
  if (
    foundPrizes.length > 0 &&
    foundMoney.length > 0
  ) {
    score += 15;
    signals.push(
      "The message combines a prize or reward claim with financial language."
    );
  }

  // Advanced scam patterns
  const emergencyMoney = [
    "stranded",
    "emergency",
    "hospital",
    "accident",
    "stolen",
    "lost my phone",
    "need money",
    "borrow me",
    "lend me",
    "send me money"
  ];

  const investmentPromises = [
    "guaranteed profit",
    "guaranteed returns",
    "double your money",
    "make money fast",
    "risk free",
    "no risk",
    "huge returns",
    "daily profit",
    "instant profit"
  ];

  const jobScam = [
    "work from home",
    "easy money",
    "earn daily",
    "job offer",
    "employment opportunity",
    "registration fee",
    "processing fee",
    "pay to get the job"
  ];

const secrecy = [
    "keep this secret",
    "keep it secret",
    "don't tell anyone",
    "don’t tell anyone",
    "do not tell anyone",
    "keep this between us",
    "tell nobody",
    "don't share this",
    "don’t share this"
  ];
  const foundEmergencyMoney = emergencyMoney.filter(word =>
    lower.includes(word)
  );

  const foundInvestmentPromises = investmentPromises.filter(word =>
    lower.includes(word)
  );

  const foundJobScam = jobScam.filter(word =>
    lower.includes(word)
  );

  const foundSecrecy = secrecy.filter(word =>
    lower.includes(word)
  );

  if (
    foundEmergencyMoney.length > 0 &&
    foundMoney.length > 0
  ) {
    score += 25;
    signals.push(
      "The message uses an emergency or personal crisis to request financial help."
    );
  }

  if (foundInvestmentPromises.length > 0) {
    score += 25;
    signals.push(
      "The message promises unusually high, guaranteed, or risk-free financial returns."
    );
  }

  if (
    foundJobScam.length > 0 &&
    (
      foundMoney.length > 0 ||
      lower.includes("fee") ||
      lower.includes("pay")
    )
  ) {
    score += 25;
    signals.push(
      "The message may be offering a job while requesting payment, fees, or promising unusually easy earnings."
    );
  }

  if (foundSecrecy.length > 0) {
    score += 15;
    signals.push(
      "The message pressures the recipient to keep the communication secret."
    );
  }

  if (
    foundPrizes.length > 0 &&
    foundLinks.length > 0
  ) {
    score += 20;
    signals.push(
      "The message combines a prize or reward claim with a link."
    );
  }

  if (
    foundInvestmentPromises.length > 0 &&
    foundLinks.length > 0
  ) {
    score += 20;
    signals.push(
      "The message combines an investment promise with a link."
    );
  }
  return getRisk(score, signals);
}
async function analyzePhone(input, env) {
  const text = input.trim();
  const digits = text.replace(/[^\d+]/g, "");
  const numberOnly = digits.replace(/\D/g, "");
const ipqsNumber =
  digits.startsWith("0") && numberOnly.length === 11
    ? "+234" + numberOnly.slice(1)
    : digits;
  let score = 0;
  const signals = [];

  // Basic validation
  if (!numberOnly || numberOnly.length < 7) {
    return getRisk(30, [
      "This does not appear to be a valid phone number."
    ]);
  }

  // International format
  if (digits.startsWith("+")) {
    if (numberOnly.length < 10 || numberOnly.length > 15) {
      score += 20;
      signals.push(
        "The international phone number has an unusual length."
      );
    } else {
      signals.push(
        "The number is written in international format."
      );
    }
  }

  // Nigerian local format
  if (digits.startsWith("0")) {
    if (numberOnly.length === 11) {
      signals.push(
        "The number appears to use a valid Nigerian local format."
      );
    } else {
      score += 20;
      signals.push(
        "The number appears to have an unusual local format."
      );
    }
  }

  // Nigerian international format
  if (digits.startsWith("+234")) {
    if (numberOnly.length !== 13) {
      score += 20;
      signals.push(
        "The Nigerian international number appears to have an unusual length."
      );
    }
  }

  // International country-code awareness
  const knownCountryCodes = [
    "+1",
    "+20",
    "+27",
    "+30",
    "+31",
    "+32",
    "+33",
    "+34",
    "+36",
    "+39",
    "+40",
    "+41",
    "+43",
    "+44",
    "+45",
    "+46",
    "+47",
    "+48",
    "+49",
    "+51",
    "+52",
    "+53",
    "+54",
    "+55",
    "+56",
    "+57",
    "+58",
    "+60",
    "+61",
    "+62",
    "+63",
    "+64",
    "+65",
    "+66",
    "+81",
    "+82",
    "+84",
    "+86",
    "+90",
    "+91",
    "+92",
    "+93",
    "+94",
    "+95",
    "+98",
    "+211",
    "+212",
    "+213",
    "+216",
    "+218",
    "+220",
    "+221",
    "+222",
    "+223",
    "+224",
    "+225",
    "+226",
    "+227",
    "+228",
    "+229",
    "+230",
    "+231",
    "+232",
    "+233",
    "+234",
    "+235",
    "+236",
    "+237",
    "+238",
    "+239",
    "+240",
    "+241",
    "+242",
    "+243",
    "+244",
    "+245",
    "+246",
    "+248",
    "+249",
    "+250",
    "+251",
    "+252",
    "+253",
    "+254",
    "+255",
    "+256",
    "+257",
    "+258",
    "+260",
    "+261",
    "+262",
    "+263",
    "+264",
    "+265",
    "+266",
    "+267",
    "+268",
    "+269",
    "+290",
    "+291",
    "+297",
    "+298",
    "+299",
    "+350",
    "+351",
    "+352",
    "+353",
    "+354",
    "+355",
    "+356",
    "+357",
    "+358",
    "+359",
    "+370",
    "+371",
    "+372",
    "+373",
    "+374",
    "+375",
    "+376",
    "+377",
    "+378",
    "+380",
    "+381",
    "+382",
    "+383",
    "+385",
    "+386",
    "+387",
    "+389",
    "+420",
    "+421",
    "+423",
    "+500",
    "+501",
    "+502",
    "+503",
    "+504",
    "+505",
    "+506",
    "+507",
    "+508",
    "+509",
    "+590",
    "+591",
    "+592",
    "+593",
    "+594",
    "+595",
    "+596",
    "+597",
    "+598",
    "+599",
    "+670",
    "+672",
    "+673",
    "+674",
    "+675",
    "+676",
    "+677",
    "+678",
    "+679",
    "+680",
    "+681",
    "+682",
    "+683",
    "+685",
    "+686",
    "+687",
    "+688",
    "+689",
    "+690",
    "+691",
    "+692",
    "+850",
    "+852",
    "+853",
    "+855",
    "+856",
    "+880",
    "+886",
    "+960",
    "+961",
    "+962",
    "+963",
    "+964",
    "+965",
    "+966",
    "+967",
    "+968",
    "+970",
    "+971",
    "+972",
    "+973",
    "+974",
    "+975",
    "+976",
    "+977",
    "+992",
    "+993",
    "+994",
    "+995",
    "+996",
    "+998"
  ];

  if (
    digits.startsWith("+") &&
    !knownCountryCodes.some(code => digits.startsWith(code))
  ) {
    score += 10;
    signals.push(
      "The country code could not be confidently identified."
    );
  }

  // Repeated digits
  if (/(\d)\1{5,}/.test(numberOnly)) {
    score += 15;
    signals.push(
      "The phone number contains an unusual sequence of repeated digits."
    );
  }


  // Very short number
  if (numberOnly.length < 10) {
    score += 15;
    signals.push(
      "The phone number is unusually short."
    );
  }

  // Suspicious Nigerian prefixes
  const suspiciousPrefixes = [
    "0909",
    "0919"
  ];

  if (
    suspiciousPrefixes.some(prefix =>
      numberOnly.startsWith(prefix)
    )
  ) {
    score += 10;
    signals.push(
      "The number uses a prefix that may require additional verification."
    );
  }

  if (signals.length === 0) {
    signals.push(
      "No obvious risk indicators were detected from the phone number itself."
    );
  }
    // IPQS phone reputation check
try {
  const response = await fetch(
    `https://www.ipqualityscore.com/api/json/phone/${encodeURIComponent(env.IPQS_API_KEY.trim())}/${encodeURIComponent(ipqsNumber)}`,
    {
      method: "GET",
      headers: {
        "IPQS-KEY": env.IPQS_API_KEY
      }
    }
  );

  if (response.ok) {
    const data = await response.json();

    if (data.success) {
      if (data.fraud_score !== undefined) {
        score += Math.round(Number(data.fraud_score) * 0.6);
        signals.push(
          `IPQS phone reputation score: ${data.fraud_score}/100.`
        );
      }

      if (data.spammer === true) {
        score += 25;
        signals.push(
          "IPQS identifies this number as associated with spam activity."
        );
      }

      if (data.risky === true) {
        score += 20;
        signals.push(
          "IPQS identifies this number as potentially risky."
        );
      }

      if (data.voip === true) {
        signals.push(
          "IPQS identifies this number as a VoIP number."
        );
      }

      if (data.active_status === false) {
        signals.push(
          "IPQS indicates that this number may not currently be active."
        );
      }
    } else {
      signals.push(
        `IPQS could not complete the reputation check: ${
          data.message || "Unknown IPQS error"
        }`
      );
    }
  } else {
    signals.push(
      `IPQS phone reputation service returned HTTP ${response.status}.`
    );
  }
} catch (error) {
  signals.push(
    "IPQS phone reputation check could not be completed."
  );
}
  return getRisk(score, signals);
}
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    if (request.method === "GET") {
      return response({
        service: "FraudShield API",
        status: "online",
        version: "2.0"
      });
    }

    if (request.method !== "POST") {
      return response(
        { error: "Use GET or POST." },
        405
      );
    }

    try {
      const body = await request.json();

      const type = body.type;
      const input = body.input;

      if (!input || typeof input !== "string") {
        return response(
          { error: "Input is required." },
          400
        );
      }

        let result;

      if (type === "website") {
        result = await analyzeWebsite(input);
      } else if (type === "phone") {
        result = await analyzePhone(input, env);
      } else if (
        type === "message" ||
        type === "email"
      ) {
        result = analyzeMessage(input);
      } else {
        result = analyzeMessage(input);
      }
      return response(result);

    } catch (error) {
      return response(
        {
          error: "Invalid request.",
          details: error.message
        },
        400
      );
    }
  }
};
