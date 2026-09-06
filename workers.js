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

  if (knownMalicious) {
    score += 60;
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
    "final warning"
  ];

  const money = [
    "send money",
    "transfer",
    "payment",
    "fee",
    "bank",
    "bitcoin",
    "crypto",
    "investment",
    "wallet",
    "deposit"
  ];

  const credentials = [
    "password",
    "pin",
    "otp",
    "verification code",
    "login",
    "signin",
    "security code"
  ];

  const prizes = [
    "winner",
    "won",
    "prize",
    "bonus",
    "reward",
    "free",
    "giveaway",
    "lottery"
  ];

  const links = [
    "http://",
    "https://",
    "www.",
    "bit.ly",
    "tinyurl"
  ];

  if (urgency.some(word => lower.includes(word))) {
    score += 20;
    signals.push(
      "The message creates urgency or pressure to act quickly."
    );
  }

  if (money.some(word => lower.includes(word))) {
    score += 20;
    signals.push(
      "The message involves money, payment, banking, investment, or transfers."
    );
  }

  if (credentials.some(word => lower.includes(word))) {
    score += 25;
    signals.push(
      "The message asks about passwords, PINs, OTPs, verification codes, or login information."
    );
  }

  if (prizes.some(word => lower.includes(word))) {
    score += 15;
    signals.push(
      "The message contains prize, reward, bonus, lottery, or free-offer language."
    );
  }

  if (links.some(word => lower.includes(word))) {
    score += 15;
    signals.push(
      "The message contains a link. Verify the destination before opening it."
    );
  }

  if (
    (lower.includes("send") || lower.includes("transfer")) &&
    (lower.includes("otp") ||
      lower.includes("password") ||
      lower.includes("pin"))
  ) {
    score += 20;
    signals.push(
      "The message combines a request for money or action with sensitive security information."
    );
  }

  return getRisk(score, signals);
}

export default {
  async fetch(request) {
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
