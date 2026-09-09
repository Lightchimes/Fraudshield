const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function getRisk(score) {
  const finalScore = Math.max(0, Math.min(100, Math.round(score)));

  if (finalScore >= 70) {
    return {
      score: finalScore,
      level: "HIGH RISK",
    };
  }

  if (finalScore >= 40) {
    return {
      score: finalScore,
      level: "MEDIUM RISK",
    };
  }

  return {
    score: finalScore,
    level: "LOWER RISK",
  };
}

/* ---------------- PHISHTANK ---------------- */

async function checkPhishTank(url) {
  try {
    const body = new URLSearchParams();
    body.set("url", url);
    body.set("format", "json");

    const result = await fetch(
      "http://checkurl.phishtank.com/checkurl/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "FraudShield/2.0",
        },
        body: body.toString(),
      }
    );

    const text = await result.text();

    if (!result.ok) {
      return {
        found: false,
        available: false,
        status: result.status,
        diagnostic: text.slice(0, 300),
      };
    }

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      return {
        found: false,
        available: false,
        status: result.status,
        diagnostic: text.slice(0, 300),
      };
    }

    const phishingResult = data?.results;

    return {
      found:
        phishingResult?.in_database === true &&
        phishingResult?.valid === true,
      available: true,
      status: result.status,
    };
  } catch (error) {
    return {
      found: false,
      available: false,
      error: error.message,
    };
  }
}

/* ---------------- WEBSITE ---------------- */

async function analyzeWebsite(input) {
  let url;

  try {
    url = new URL(input.trim());
  } catch {
    return {
      ...getRisk(25),
      signals: ["The submitted website address is not a valid URL."],
      advice: "Check the address carefully before visiting it.",
    };
  }

  let score = 0;
  const signals = [];

  const hostname = url.hostname.toLowerCase();

  const knownMaliciousDomains = [
    "qujqmtk.com",
  ];

  const knownMalicious = knownMaliciousDomains.some(
    (domain) =>
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
      "microsoftonline.com",
    ],
    google: ["google.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com"],
    binance: ["binance.com"],
  };

  const hostnameLabels = hostname.split(".");

  const suspiciousBrandMatch = Object.entries(
    officialBrandDomains
  ).some(([brand, officialDomains]) => {
    const brandInHostname = hostnameLabels.some((label) =>
      label.includes(brand)
    );

    const isOfficial = officialDomains.some(
      (domain) =>
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
    signals.push("The website does not use HTTPS.");
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
      "The hostname contains punycode, which can sometimes be used for lookalike domains."
    );
  }

  if ((hostname.match(/-/g) || []).length >= 3) {
    score += 10;
    signals.push(
      "The hostname contains an unusually high number of hyphens."
    );
  }

  if (hostname.length > 50) {
    score += 10;
    signals.push("The hostname is unusually long.");
  }

  if (input.includes("@")) {
    score += 25;
    signals.push(
      "The URL contains an @ symbol, which can be used to disguise the real destination."
    );
  }

  const suspiciousWords = [
    "login",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "update",
    "confirm",
    "password",
    "wallet",
    "payment",
    "signin",
    "unlock",
  ];

  const suspiciousWordCount = suspiciousWords.filter(
    (word) => input.toLowerCase().includes(word)
  ).length;

  if (suspiciousWordCount >= 2) {
    score += 20;
    signals.push(
      "The URL contains several words commonly associated with phishing pages."
    );
  }

  const sensitiveTargets = [
    "password",
    "bank",
    "wallet",
    "payment",
    "account",
    "crypto",
  ];

  const hasSensitiveTarget = sensitiveTargets.some((word) =>
    input.toLowerCase().includes(word)
  );

  if (hasSensitiveTarget && suspiciousWordCount >= 1) {
    score += 15;
    signals.push(
      "The URL appears to target sensitive account or financial information."
    );
  }

  if (hostname.split(".").length >= 4) {
    score += 10;
    signals.push(
      "The hostname contains an unusually deep subdomain structure."
    );
  }

  if (input.length > 120) {
    score += 10;
    signals.push("The URL is unusually long.");
  }

  if (/%[0-9a-fA-F]{2}/.test(input)) {
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
    "is.gd",
    "ow.ly",
  ];

  if (shorteners.some((domain) => hostname === domain)) {
    score += 15;
    signals.push(
      "The URL uses a link-shortening service, which hides the final destination."
    );
  }

  const suspiciousDomainPatterns = [
    /^login-/,
    /^verify-/,
    /^secure-/,
    /^account-/,
    /^update-/,
    /^confirm-/,
    /-login$/,
    /-verify$/,
    /-secure$/,
    /-account$/,
  ];

  if (
    suspiciousDomainPatterns.some((pattern) =>
      pattern.test(hostname)
    )
  ) {
    score += 20;
    signals.push(
      "The domain follows a suspicious login, verification, security, or account pattern."
    );
  }

  const phishTank = await checkPhishTank(url.href);

  if (phishTank.found) {
    score += 50;
    signals.push(
      "PhishTank identifies this URL as a confirmed phishing URL."
    );
  } else if (!phishTank.available) {
    signals.push(
      "External phishing intelligence was unavailable. This result is based on FraudShield's own analysis."
    );
  }

  const risk = getRisk(score);

  return {
    ...risk,
    type: "website",
    input: input.trim(),
    signals,
    advice:
      risk.score >= 70
        ? "Do not enter passwords, banking details, OTPs, or payment information on this website."
        : risk.score >= 40
        ? "Proceed carefully and verify the website through an official source."
        : "No major warning signs were detected by the current FraudShield checks.",
  };
}

/* ---------------- MESSAGE ---------------- */

async function analyzeMessage(input) {
  const text = input.trim().toLowerCase();

  let score = 0;
  const signals = [];

  const urgency = [
    "urgent",
    "immediately",
    "right now",
    "act now",
    "asap",
    "within 24 hours",
    "last chance",
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
    "naira",
  ];

  const credentials = [
    "password",
    "otp",
    "one time password",
    "verification code",
    "pin",
    "cvv",
    "card number",
    "login",
    "username",
  ];

  const prizes = [
    "you have won",
    "winner",
    "congratulations",
    "prize",
    "lottery",
    "reward",
    "claim your",
  ];

  const links = [
    "http://",
    "https://",
    "www.",
  ];

  const threats = [
    "account will be closed",
    "account suspended",
    "police",
    "arrest",
    "legal action",
    "blocked",
    "deactivated",
  ];

  const impersonation = [
    "this is your boss",
    "this is me",
    "i am your boss",
    "your pastor",
    "your manager",
    "customer service",
    "support team",
    "bank representative",
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
    "don’t share this",
  ];

  const contains = (list) =>
    list.some((word) => text.includes(word));

  if (contains(urgency)) {
    score += 20;
    signals.push("The message uses urgency or pressure.");
  }

  if (contains(money)) {
    score += 20;
    signals.push(
      "The message involves money, payments, banking, or financial assets."
    );
  }

  if (contains(credentials)) {
    score += 25;
    signals.push(
      "The message requests or mentions sensitive credentials."
    );
  }

  if (contains(prizes)) {
    score += 15;
    signals.push(
      "The message contains prize or reward language."
    );
  }

  if (contains(links)) {
    score += 15;
    signals.push(
      "The message contains a web link."
    );
  }

  if (contains(threats)) {
    score += 20;
    signals.push(
      "The message uses threats or consequences to create pressure."
    );
  }

  if (contains(impersonation)) {
    score += 15;
    signals.push(
      "The message may involve impersonation."
    );
  }

  if (contains(urgency) && contains(money)) {
    score += 20;
    signals.push(
      "Urgency is combined with a financial request."
    );
  }

  if (contains(urgency) && contains(credentials)) {
    score += 20;
    signals.push(
      "Urgency is combined with a request for sensitive information."
    );
  }

  if (contains(prizes) && contains(money)) {
    score += 15;
    signals.push(
      "Prize language is combined with a financial request."
    );
  }

  if (
    contains(["stranded", "accident", "hospital", "emergency", "stolen"]) &&
    contains(money)
  ) {
    score += 25;
    signals.push(
      "An emergency or personal crisis is combined with a request for money."
    );
  }

  if (
    contains(["guaranteed", "double your money", "guaranteed profit"]) &&
    contains(["investment", "crypto", "bitcoin", "forex"])
  ) {
    score += 25;
    signals.push(
      "The message contains potentially deceptive investment promises."
    );
  }

  if (
    contains(["job", "employment", "work from home"]) &&
    contains(["registration fee", "processing fee", "payment"])
  ) {
    score += 25;
    signals.push(
      "The message may contain a job scam involving an upfront payment."
    );
  }

  if (contains(secrecy)) {
    score += 15;
    signals.push(
      "The sender pressures the recipient to keep the matter secret."
    );
  }

  if (contains(prizes) && contains(links)) {
    score += 20;
    signals.push(
      "Prize language is combined with a link."
    );
  }

  if (
    contains(["investment", "crypto", "bitcoin", "forex"]) &&
    contains(links)
  ) {
    score += 20;
    signals.push(
      "An investment or cryptocurrency message contains a link."
    );
  }

  const risk = getRisk(score);

  return {
    ...risk,
    type: "message",
    input: input.trim(),
    signals,
    advice:
      risk.score >= 70
        ? "Do not send money, OTPs, passwords, PINs, or other sensitive information."
        : risk.score >= 40
        ? "Verify the sender independently before taking action."
        : "No major scam indicators were detected by the current checks.",
  };
}

/* ---------------- PHONE ---------------- */

async function analyzePhone(input, env) {
  const raw = input.trim();
  const numberOnly = raw.replace(/\D/g, "");

  let score = 0;
  const signals = [];

  const isNigerianLocal =
    /^0\d{10}$/.test(numberOnly);

  const isNigerianInternational =
    /^\+?234\d{10}$/.test(
      raw.replace(/[\s()-]/g, "")
    );

  if (isNigerianLocal) {
    signals.push(
      "The number matches a Nigerian local phone-number format."
    );
  } else if (isNigerianInternational) {
    signals.push(
      "The number matches the international Nigerian +234 format."
    );
  } else if (numberOnly.length < 7) {
    score += 30;
    signals.push(
      "The phone number appears too short or incomplete."
    );
  } else {
    signals.push(
      "The number uses an international or non-standard format."
    );
  }

  if (/^(\d)\1+$/.test(numberOnly)) {
    score += 15;
    signals.push(
      "The number contains repeated digits."
    );
  }

  if (
    isNigerianLocal &&
    (numberOnly.startsWith("0909") ||
      numberOnly.startsWith("0919"))
  ) {
    score += 10;
    signals.push(
      "The Nigerian number uses a prefix flagged by FraudShield for additional caution."
    );
  }

  const ipqsKey = env?.IPQS_API_KEY?.trim();

  if (!ipqsKey) {
    signals.push(
      "IPQS secret binding detected: NO. The IPQS_API_KEY runtime secret is missing."
    );
  } else {
    signals.push(
      "IPQS secret binding detected: YES."
    );

    const digits = numberOnly;

    const ipqsNumber =
      digits.startsWith("0") && digits.length === 11
        ? "+234" + digits.slice(1)
        : digits;

    try {
      const ipqsUrl =
        "https://www.ipqualityscore.com/api/json/phone" +
        "?phone=" +
        encodeURIComponent(ipqsNumber) +
        "&country=NG";

      const ipqsResponse = await fetch(ipqsUrl, {
        method: "GET",
        headers: {
          "IPQS-KEY": ipqsKey,
          "Accept": "application/json",
        },
      });

      const ipqsText = await ipqsResponse.text();

      let data = null;

      try {
        data = JSON.parse(ipqsText);
      } catch {
        data = null;
      }

      if (!ipqsResponse.ok) {
        signals.push(
          "IPQS HTTP error: " +
            ipqsResponse.status +
            "."
        );

        if (ipqsText) {
          signals.push(
            "IPQS response: " +
              ipqsText.slice(0, 250)
          );
        }
      } else if (!data) {
        signals.push(
          "IPQS returned a response that was not valid JSON."
        );
      } else if (data.success === false) {
        signals.push(
          "IPQS rejected the reputation request: " +
            (data.message || "Unknown IPQS error.")
        );
      } else {
        const fraudScore =
          Number(data.fraud_score) || 0;

        if (fraudScore >= 90) {
          score += 60;
          signals.push(
            "IPQS reports a very high phone fraud score: " +
              fraudScore +
              "/100."
          );
        } else if (fraudScore >= 85) {
          score += 50;
          signals.push(
            "IPQS reports a high phone fraud score: " +
              fraudScore +
              "/100."
          );
        } else if (fraudScore >= 75) {
          score += 35;
          signals.push(
            "IPQS reports a suspicious phone fraud score: " +
              fraudScore +
              "/100."
          );
        } else if (fraudScore > 0) {
          score += Math.round(fraudScore * 0.6);
          signals.push(
            "IPQS phone fraud score: " +
              fraudScore +
              "/100."
          );
        } else {
          signals.push(
            "IPQS returned a low or zero fraud score."
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
            "IPQS flags this phone number as risky."
          );
        }

        if (data.spammer === true) {
          score += 25;
          signals.push(
            "IPQS identifies this number as associated with spam activity."
          );
        }

        if (data.active === false) {
          score += 10;
          signals.push(
            "IPQS reports that the phone line is not currently active."
          );
        }

        if (data.valid === false) {
          score += 20;
          signals.push(
            "IPQS reports that the phone number is invalid."
          );
        }

        if (data.VOIP === true) {
          signals.push(
            "IPQS identifies the number as a VOIP number."
          );
        }

        if (data.prepaid === true) {
          signals.push(
            "IPQS identifies the number as prepaid."
          );
        }

        if (data.country) {
          signals.push(
            "IPQS country: " + data.country + "."
          );
        }

        if (data.carrier) {
          signals.push(
            "IPQS carrier: " + data.carrier + "."
          );
        }

        if (data.line_type) {
          signals.push(
            "IPQS line type: " + data.line_type + "."
          );
        }

        if (data.request_id) {
          signals.push(
            "IPQS request ID: " +
              data.request_id +
              "."
          );
        }
      }
    } catch (error) {
      signals.push(
        "IPQS connection error: " +
          error.message
      );
    }
  }

  const risk = getRisk(score);

  return {
    ...risk,
    type: "phone",
    input: raw,
    signals,
    advice:
      risk.score >= 70
        ? "Do not send money, OTPs, passwords, or other sensitive information to this number."
        : risk.score >= 40
        ? "Verify the caller or sender independently before taking action."
        : "No major phone-risk indicators were detected by the current FraudShield checks.",
  };
}

/* ---------------- WORKER ---------------- */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders,
      });
    }

    const url = new URL(request.url);

    if (request.method === "GET") {
      return response({
        service: "FraudShield API",
        status: "online",
        version: "2.0",
      });
    }

    if (request.method !== "POST") {
      return response(
        {
          error: "Method not allowed",
        },
        405
      );
    }

    try {
      const body = await request.json();

      const type = String(
        body?.type || ""
      ).toLowerCase();

      const input = String(
        body?.input || ""
      ).trim();

      if (!input) {
        return response(
          {
            error: "Input is required.",
          },
          400
        );
      }

      let result;

      if (type === "website" || type === "url") {
        result = await analyzeWebsite(input);
      } else if (
        type === "message" ||
        type === "email"
      ) {
        result = await analyzeMessage(input);
      } else if (type === "phone") {
        result = await analyzePhone(input, env);
      } else {
        return response(
          {
            error:
              "Unsupported type. Use website, message, email, or phone.",
          },
          400
        );
      }

      return response(result);
    } catch (error) {
      return response(
        {
          error: "Server error.",
          details: error.message,
        },
        500
      );
    }
  },
};
