
const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const { promisify } = require("util");

const app = express();
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

app.use(cors());
app.use(express.json());

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

// 3. Run a real DNSSEC test for an allowlisted domain
app.post("/api/dnssec/test", async (req, res) => {
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

  const isLabDomain = dnsTests.some((test) => test.domain === domain);

// Keep the three controlled lab scenarios available.
const isValidDomain =
  domain.length <= 253 &&
  domain.endsWith(".") === false &&
  domain.split(".").length >= 2 &&
  domain.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );

if (!isValidDomain) {
  return res.status(400).json({
    success: false,
    error: "Enter a valid domain name, such as example.com.",
    availableDomains: dnsTests.map((test) => test.domain),
  });
}

  try {
    const data = await queryResolver(domain);

    res.json({
      success: true,
      mode: "live",
      resolverConnected: true,
      message: "Result obtained from the Unbound resolver.",
      data,
    });
  } catch (error) {
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
