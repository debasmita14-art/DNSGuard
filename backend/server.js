
const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const { promisify } = require("util");
const rateLimit = require("express-rate-limit");
const fs = require("fs/promises");
const path = require("path");;

const app = express();
app.set("trust proxy", 1);
const PORT = 3001;
const execFileAsync = promisify(execFile);

// Only allow the three configured lab test domains.
const dnsTests = [
  {
    domain: "secure.lab.test",
    expectedStatus: "SECURE",
  },
  {
    domain: "insecure.lab.test",
    expectedStatus: "INSECURE",
  },
  {
    domain: "www.bogus.lab.test",
    expectedStatus: "BOGUS",
  },
];

// Persistent audit log file
const LOG_FILE = path.join(__dirname, "dns-logs.jsonl");

// Explain DNSSEC results using the resolver's observed evidence.
function explainResult(data) {
  if (data.status === "SECURE") {
    return {
      title: "DNSSEC validation successful",
      explanation:
        "The resolver returned NOERROR and the AD flag, indicating that it validated the DNS data using DNSSEC.",
      evidence: [
        "Response code: NOERROR",
        "Authenticated Data (AD): present",
      ],
    };
  }

  if (data.status === "INSECURE") {
    return {
      title: "DNS response is not DNSSEC-authenticated",
      explanation:
        "The resolver returned NOERROR without the AD flag. This is consistent with an unsigned or otherwise non-authenticated DNS response; it does not by itself indicate an attack.",
      evidence: [
        "Response code: NOERROR",
        "Authenticated Data (AD): absent",
      ],
    };
  }

  if (data.status === "BOGUS") {
    return {
      title: "DNSSEC validation failed",
      explanation:
        "The resolver returned SERVFAIL with evidence of a DNSSEC validation failure. Possible causes include invalid or expired signatures, incorrect DNSSEC configuration, or tampering. Further investigation is needed to determine the cause.",
      evidence: [
        "Response code: SERVFAIL",
        "DNSSEC validation failure detected",
      ],
    };
  }

  return {
    title: "DNS result could not be classified",
    explanation:
      "The available resolver response did not provide enough evidence to classify this result as secure, insecure, or DNSSEC-bogus. Check resolver connectivity and diagnostic output.",
    evidence: [
      `Response code: ${data.result || "Unavailable"}`,
      "Classification requires further investigation",
    ],
  };
}

// Append one actual test event as a JSON Lines record.
async function writeTestLog(data, eventType = "DNSSEC_TEST") {
  const explanation = explainResult(data);

  const entry = {
    timestamp: new Date().toISOString(),
    eventType,
    domain: data.domain,
    status: data.status,
    responseCode: data.result,
    authenticated: data.authenticated,
    answer: data.answer,
    latencyMs: data.queryTimeMs,
    flags: data.flags,
    explanation: explanation.explanation,
    evidence: explanation.evidence,
  };

  await fs.appendFile(
    LOG_FILE,
    JSON.stringify(entry) + "\n",
    "utf8"
  );

  return entry;
}

app.use(
  cors({
    origin: "https://dns-guard-pink.vercel.app",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json({ limit: "10kb" }));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many requests. Please wait a minute and try again.",
  },
});

app.use("/api", apiLimiter);
/**
 * Run a real DNSSEC query through Unbound in WSL.
 * Arguments are passed separately; user input is never
 * interpreted as a shell command.
 */
async function queryResolver(domain) {
  const startedAt = Date.now();

  let stdout;

  try {
    const result = await execFileAsync(
      "wsl.exe",
      [
        "--",
        "dig",
        "@127.0.0.1",
        domain,
        "A",
        "+dnssec",
        "+noall",
        "+comments",
        "+answer",
        "+stats",
      ],
      {
        timeout: 7000,
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      }
    );

    stdout = result.stdout;
  } catch (error) {
    // dig may exit with a nonzero code for SERVFAIL.
    // Its stdout can still contain a valid DNS response.
    stdout = error.stdout || "";

    if (!stdout.includes("status:")) {
      throw new Error(
        "Could not query Unbound through WSL. Check that WSL and Unbound are running."
      );
    }
  }

  const header = stdout.match(/status:\s*([A-Z]+)/);
  if (!header) {
    throw new Error("The resolver returned an unrecognised response.");
  }

  const resultCode = header[1];
  const flagsLine = stdout.match(/flags:\s*([^;]+)/);
  const flags = flagsLine ? flagsLine[1].trim().split(/\s+/) : [];
  const authenticated = flags.includes("ad");

  const answerMatch = stdout.match(
    /^\S+\s+\d+\s+IN\s+A\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/m
  );

  const queryTimeMatch = stdout.match(/Query time:\s*(\d+)\s*msec/i);
  const queryTimeMs = queryTimeMatch
    ? Number(queryTimeMatch[1])
    : Date.now() - startedAt;

  const isDnssecBogus =
    resultCode === "SERVFAIL" &&
    /DNSSEC Bogus|signature crypto failed|EDE:\s*6/i.test(stdout);

  let status = "ERROR";

  if (resultCode === "SERVFAIL" && isDnssecBogus) {
    status = "BOGUS";
  } else if (resultCode === "NOERROR" && authenticated) {
    status = "SECURE";
  } else if (resultCode === "NOERROR" && !authenticated) {
    status = "INSECURE";
  }

  return {
    domain,
    status,
    result: resultCode,
    authenticated,
    answer: answerMatch ? answerMatch[1] : null,
    queryTimeMs,
    flags,
    source: "Unbound via WSL",
    checkedAt: new Date().toISOString(),
  };
}

 // WSL metrics bridge
app.get("/api/metrics", async (req, res) => {
  try {
    const response = await fetch("http://localhost:8000/api/metrics");

    if (!response.ok) {
      return res.status(502).json({
        success: false,
        message: `WSL metrics service returned ${response.status}`,
      });
    }

    const metrics = await response.json();
    res.json({
      success: true,
      mode: "live",
      data: metrics,
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      message: "WSL metrics service is unavailable. Check that the metrics server is running.",
    });
  }
});

// 1. Health check


// 1. Health check
app.get("/api/health", async (req, res) => {
  try {
    await queryResolver("secure.lab.test");

    res.json({
      success: true,
      service: "DNSGuard API",
      mode: "live",
      resolverConnected: true,
      resolver: "Unbound via WSL",
      message: "Live DNSSEC resolver checks are working.",
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      service: "DNSGuard API",
      mode: "unavailable",
      resolverConnected: false,
      message: error.message,
    });
  }
});
// 2. Run all three real DNSSEC test cases
app.get("/api/queries", async (req, res) => {
  try {
    const results = await Promise.all(
      dnsTests.map((test) => queryResolver(test.domain))
    );

    res.json({
      success: true,
      mode: "live",
      count: results.length,
      data: results,
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      mode: "unavailable",
      error: error.message,
      data: [],
    });
  }
});

// 3. Retrieve saved DNSSEC test logs
app.get("/api/logs", async (req, res) => {
  try {
    const contents = await fs.readFile(LOG_FILE, "utf8");

    const logs = contents
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line))
      .reverse()
      .slice(0, 100);

    res.json({
      success: true,
      count: logs.length,
      data: logs,
    });
  } catch (error) {
    if (error.code === "ENOENT") {
      return res.json({
        success: true,
        count: 0,
        data: [],
      });
    }

    console.error("Could not read DNSSEC logs:", error.message);

    res.status(500).json({
      success: false,
      error: "Could not retrieve DNSSEC logs.",
    });
  }
});

// 4. Run a real DNSSEC test for an allowlisted domain
app.post("/api/dnssec/test", async (req, res) => {
// Rogue Gateway Simulation — demonstration only; does not inspect the real network.
app.post("/api/gateway/simulate", (req, res) => {
  const trusted = {
    ip: "192.168.1.1",
    mac: "AA:BB:CC:DD:EE:01",
  };

  const scenarios = {
    trusted: {
      ip: "192.168.1.1",
      mac: "AA:BB:CC:DD:EE:01",
    },
    rogueMac: {
      ip: "192.168.1.1",
      mac: "AA:BB:CC:DD:EE:99",
    },
    rogueIp: {
      ip: "192.168.1.99",
      mac: "AA:BB:CC:DD:EE:01",
    },
  };

  const scenario =
    typeof req.body?.scenario === "string"
      ? req.body.scenario
      : "rogueMac";

  if (!Object.prototype.hasOwnProperty.call(scenarios, scenario)) {
    return res.status(400).json({
      success: false,
      error: "Choose trusted, rogueMac, or rogueIp.",
    });
  }

  const observed = scenarios[scenario];
  const matched =
    observed.ip === trusted.ip && observed.mac === trusted.mac;

  res.json({
    success: true,
    mode: "SIMULATION",
    trusted,
    observed,
    status: matched ? "GATEWAY MATCH" : "ROGUE GATEWAY SUSPECTED",
    matched,
    explanation: matched
      ? "The simulated gateway matches the trusted baseline."
      : "The simulated gateway differs from the trusted baseline.",
    notice: "Simulated comparison only; no live network attack was detected.",
    timestamp: new Date().toISOString(),
  });
});
  const domain =
    typeof req.body?.domain === "string"
      ? req.body.domain.trim().toLowerCase()
      : "";

  if (!domain) {
    return res.status(400).json({
      success: false,
      error: "Please provide a valid domain.",
    });
  }

    // Allow valid DNS names while keeping shell execution safe.
    const domainPattern =
    /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
  if (
    !domainPattern.test(domain) ||
    !domain.includes(".") ||
    domain.split(".").some((label) => label.length > 63)
  ) {
    return res.status(400).json({
      success: false,
      error: "Please enter a valid domain name, such as example.com.",
    });
  }

  try {
    const data = await queryResolver(domain);
    const explanation = explainResult(data);
    const logEntry = await writeTestLog(data, "MANUAL_DNSSEC_TEST");

    res.json({
      success: true,
      mode: "live",
      resolverConnected: true,
      message: "Result obtained from the Unbound resolver.",
      data: {
        ...data,
        explanation,
      },
      log: {
        timestamp: logEntry.timestamp,
        eventType: logEntry.eventType,
      },
    });
  } catch (error) {
    console.error("DNSSEC test failed:", error.message);

    res.status(503).json({
      success: false,
      mode: "unavailable",
      resolverConnected: false,
      error: error.message,
    });
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`DNSGuard API running at http://localhost:${PORT}`);
});
