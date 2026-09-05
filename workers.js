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

function analyzeWebsite(input) {
  const text = input.trim();
  let score = 0;
  const signals = [];

  try {
    const url = new URL(text);

    if (url.protocol !== "https:") {
      score += 20;
      signals.push("The website does not use HTTPS.");
    }

    if (url.hostname.includes("xn--")) {
      score += 25;
      signals.push("The domain uses punycode, which can sometimes hide look-alike characters.");
    }

    if ((url.hostname.match(/-/g) || []).length >= 3) {
      score += 10;
      signals.push("The domain contains many hyphens.");
    }

    const suspiciousWords = [
      "verify", "secure", "login", "account", "update",
      "confirm", "wallet", "claim", "bonus", "reward",
      "urgent", "suspended", "password"
    ];

    const lower = text.toLowerCase();

    const found = suspiciousWords.filter(word => lower.includes(word));

    if (found.length >= 2) {
      score += 20;
      signals.push("The address contains several words commonly used in deceptive links.");
    }

    if (/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(text)) {
      score += 25;
      signals.push("The link uses an IP address instead of a normal domain name.");
    }

    if (text.length > 120) {
      score += 10;
      signals.push("The URL is unusually long.");
    }

    if (text.includes("@")) {
      score += 20;
      signals.push("The URL contains an @ symbol, which can be used to disguise the real destination.");
    }

  } catch {
    score += 10;
    signals.push("This does not appear to be a normal website URL.");
  }

  score = Math.min(score, 100);

  return {
    score,
    level: score >= 60 ? "HIGH RISK" : score >= 30 ? "MEDIUM RISK" : "LOWER RISK",
    signals: signals.length ? signals : ["No obvious scam signals were detected by the current rules."],
    advice: score >= 60
      ? "Do not enter passwords, OTPs, banking information, or payment details."
      : "Still verify the website independently before sharing sensitive information."
  };
}

function analyzeMessage(input) {
  const text = input.trim();
  const lower = text.toLowerCase();

  let score = 0;
  const signals = [];

  const urgency = ["urgent", "immediately", "act now", "within 24 hours", "suspended"];
  const money = ["send money", "transfer", "payment", "fee", "bank", "bitcoin", "crypto"];
  const credentials = ["password", "pin", "otp", "verification code", "login"];
  const prizes = ["winner", "won", "prize", "bonus", "reward", "free"];
  const links = ["http://", "https://", "www."];

  if (urgency.some(word => lower.includes(word))) {
    score += 20;
    signals.push("The message creates urgency or pressure to act quickly.");
  }

  if (money.some(word => lower.includes(word))) {
    score += 20;
    signals.push("The message involves money, payment, banking, or transfers.");
  }

  if (credentials.some(word => lower.includes(word))) {
    score += 25;
    signals.push("The message asks about passwords, PINs, OTPs, or login information.");
  }

  if (prizes.some(word => lower.includes(word))) {
    score += 15;
    signals.push("The message contains prize, reward, bonus, or free-offer language.");
  }

  if (links.some(word => lower.includes(word))) {
    score += 15;
    signals.push("The message contains a link. Verify the destination before opening it.");
  }

  score = Math.min(score, 100);

  return {
    score,
    level: score >= 60 ? "HIGH RISK" : score >= 30 ? "MEDIUM RISK" : "LOWER RISK",
    signals: signals.length ? signals : ["No obvious scam signals were detected by the current rules."],
    advice: score >= 60
      ? "Do not send money, OTPs, passwords, PINs, or banking details. Verify the sender independently."
      : "Be cautious and verify the sender before taking action."
  };
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
        version: "1.0"
      });
    }

    if (request.method !== "POST") {
      return response({ error: "Use GET or POST." }, 405);
    }

    try {
      const body = await request.json();
      const type = body.type;
      const input = body.input;

      if (!input || typeof input !== "string") {
        return response({ error: "Input is required." }, 400);
      }

      let result;

      if (type === "website") {
        result = analyzeWebsite(input);
      } else if (type === "message" || type === "email") {
        result = analyzeMessage(input);
      } else {
        result = analyzeMessage(input);
      }

      return response(result);

    } catch (error) {
      return response({
        error: "Invalid request.",
        details: error.message
      }, 400);
    }
  }
};
