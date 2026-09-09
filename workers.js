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
    "â‚¦",
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
    "donâ€™t tell anyone",
    "do not tell anyone",
    "keep this between us",
    "tell nobody",
    "don't share this",
    "donâ€™t share this"
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

  const rawIpqsKey =
  env && env.IPQS_API_KEY
    ? String(env.IPQS_API_KEY)
    : "";

const ipqsKey =
  rawIpqsKey.trim();

signals.push(
  "IPQS secret binding detected: " +
  (ipqsKey ? "YES" : "NO") +
  "."
);

if (ipqsKey) {
  signals.push(
    "IPQS secret length: " +
    ipqsKey.length +
    " characters."
  );

  signals.push(
    "IPQS secret had surrounding whitespace: " +
    (rawIpqsKey !== ipqsKey ? "YES" : "NO") +
    "."
  );

  signals.push(
    "IPQS secret appears to be a placeholder: " +
    (
      ipqsKey === "YOUR_API_KEY_HERE" ||
      ipqsKey === "YOUR_API_KEY"
        ? "YES"
        : "NO"
    ) +
    "."
  );
}

  if (!ipqsKey) {
    signals.push(
      "IPQS secret binding detected: NO."
    );
  } else {
    signals.push(
      "IPQS secret binding detected: YES."
    );

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

  return {
    type: "phone",
    ...risk,
    signals,
    advice:
      risk.score >= 70
        ? "Treat this number as high risk. Do not send money, OTPs, passwords, or banking information."
        : risk.score >= 40
        ? "Use caution and independently verify the caller before trusting requests for money or sensitive information."
        : "No major warning signs were detected by the current phone checks."
  };
}

async function analyzeAccount(input) {
  const text =
    String(input || "").trim();

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
        "Enter a username, profile URL, or account information to analyze."
    };
  }

  if (
    /verified|official|support|admin|manager|ceo|crypto|investment|giveaway|prize/i.test(text)
  ) {
    score += 20;

    signals.push(
      "The account information contains terms commonly seen in impersonation, investment, support, or giveaway scams."
    );
  }

  if (
    /telegram|whatsapp|facebook|instagram|tiktok|twitter|x\.com|youtube|linkedin/i.test(text)
  ) {
    signals.push(
      "A social-media or messaging platform is referenced."
    );
  }

  if (
    /https?:\/\/|www\./i.test(text)
  ) {
    score += 10;

    signals.push(
      "The account information contains a web address."
    );
  }

  const risk = getRisk(score);

  return {
    type: "account",
    ...risk,
    signals,
    advice:
      risk.score >= 70
        ? "Do not trust the account without independent verification."
        : risk.score >= 40
        ? "Verify the account through the platform's official channels."
        : "No major warning signs were detected by the current account checks."
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
      } else if (
        type === "message" ||
        type === "email"
      ) {
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
      } else {
        return response(
          {
            error:
              "Unknown analysis type. Use website, message, phone, or account."
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
