// FraudShield V2 — Basic Website Risk Engine
// Defensive anti-fraud prototype

function analyzeWebsite(url) {
  let score = 0;
  const signals = [];

  if (!url || !url.trim()) {
    return {
      score: 0,
      level: "NO INPUT",
      signals: ["Please enter a website address."]
    };
  }

  let cleanUrl = url.trim();

  // Add protocol if the user did not provide one
  if (!/^https?:\/\//i.test(cleanUrl)) {
    cleanUrl = "https://" + cleanUrl;
  }

  let site;

  try {
    site = new URL(cleanUrl);
  } catch (error) {
    return {
      score: 80,
      level: "HIGH RISK",
      signals: ["The website address does not appear to be a valid URL."]
    };
  }

  const hostname = site.hostname.toLowerCase();
  const fullUrl = cleanUrl.toLowerCase();

  // 1. HTTPS check
  if (site.protocol !== "https:") {
    score += 15;
    signals.push("The website does not use HTTPS.");
  }

  // 2. Punycode / possible look-alike domain
  if (hostname.includes("xn--")) {
    score += 25;
    signals.push("The domain uses punycode, which can sometimes be used for look-alike domains.");
  }

  // 3. Too many hyphens
  const hyphens = (hostname.match(/-/g) || []).length;

  if (hyphens >= 3) {
    score += 10;
    signals.push("The domain contains an unusually high number of hyphens.");
  }

  // 4. Suspicious words
  const suspiciousWords = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "wallet",
    "bonus",
    "claim",
    "gift",
    "support",
    "password",
    "bank"
  ];

  const foundWords = suspiciousWords.filter(word =>
    hostname.includes(word)
  );

  if (foundWords.length >= 2) {
    score += 15;
    signals.push(
      "The domain contains words commonly associated with phishing or impersonation."
    );
  }

  // 5. IP address instead of normal domain
  const ipPattern =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (ipPattern.test(hostname)) {
    score += 25;
    signals.push("The website uses an IP address instead of a normal domain name.");
  }

  // 6. Very long URL
  if (fullUrl.length > 120) {
    score += 10;
    signals.push("The URL is unusually long.");
  }

  // 7. Embedded username/password
  if (site.username || site.password) {
    score += 25;
    signals.push("The URL contains embedded login credentials.");
  }

  // Keep score between 0 and 100
  score = Math.min(score, 100);

  let level;

  if (score >= 60) {
    level = "HIGH RISK";
  } else if (score >= 30) {
    level = "MEDIUM RISK";
  } else {
    level = "LOWER RISK";
  }

  if (signals.length === 0) {
    signals.push(
      "No obvious warning signals were detected by the current rule engine."
    );
  }

  return {
    score,
    level,
    signals
  };
}

// Example:
// console.log(analyzeWebsite("https://example.com"));
