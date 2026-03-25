const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

// --- Configuration (set via environment variables after DevOps Cockpit registration) ---
const IH_GATEWAY = "https://gateway.eu1.mindsphere.io";
const IH_TENANT = process.env.IH_TENANT || "envetec";
const IH_APP_NAME = process.env.IH_APP_NAME || "";
const IH_APP_VERSION = process.env.IH_APP_VERSION || "1.0.0";
const IH_CLIENT_ID = process.env.IH_CLIENT_ID || "";
const IH_CLIENT_SECRET = process.env.IH_CLIENT_SECRET || "";

// --- Serve the frontend ---
app.use(express.static(path.join(__dirname, "public")));

// --- Diagnostic endpoint: dump everything IH sends us ---
app.get("/api/debug/headers", (req, res) => {
  const headers = { ...req.headers };
  const cookies = parseCookies(req.headers.cookie || "");

  // Try to decode bearer token if present
  let tokenClaims = null;
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    try {
      // Decode without verification - we just want the claims
      tokenClaims = jwt.decode(authHeader.slice(7), { complete: true });
    } catch (e) {
      tokenClaims = { error: e.message };
    }
  }

  res.json({
    message: "Diagnostic dump of everything IH sent to this app",
    headers,
    cookies,
    tokenClaims,
    query: req.query,
    url: req.originalUrl,
  });
});

// --- Extract user identity from the IH session ---
app.get("/api/me", (req, res) => {
  const userInfo = extractUserInfo(req);
  if (!userInfo) {
    return res.status(401).json({
      error: "Could not extract user identity",
      hint: "Check /api/debug/headers to see what IH is sending",
    });
  }
  res.json(userInfo);
});

// --- Debug: test the full token chain step by step ---
app.get("/api/debug/token-chain", async (req, res) => {
  const steps = {};

  // Step 1: Extract user info
  const userInfo = extractUserInfo(req);
  steps.userInfo = userInfo || { error: "No user identity found" };

  // Step 2: Try getting a technical token (no impersonation)
  try {
    const techToken = await getTechnicalToken();
    const decoded = jwt.decode(techToken);
    steps.technicalToken = {
      success: true,
      scope: decoded?.scope,
      sub: decoded?.sub,
      email: decoded?.email,
      cat: decoded?.cat,
    };
  } catch (e) {
    steps.technicalToken = { error: e.message };
  }

  // Step 3: Try getting an impersonated token
  if (userInfo?.email) {
    try {
      const impToken = await getImpersonatedToken(userInfo);
      const decoded = jwt.decode(impToken);
      steps.impersonatedToken = {
        success: true,
        scope: decoded?.scope,
        sub: decoded?.sub,
        email: decoded?.email,
        user_name: decoded?.user_name,
        cat: decoded?.cat,
      };
    } catch (e) {
      steps.impersonatedToken = { error: e.message };
    }
  }

  // Step 4: Try calling Cases API with technical token
  try {
    const techToken = await getTechnicalToken();
    const response = await fetch(
      `${IH_GATEWAY}/api/casemanagement/v3/cases?size=1`,
      { headers: { Authorization: `Bearer ${techToken}` } }
    );
    steps.casesApiWithTechToken = {
      status: response.status,
      ok: response.ok,
      body: response.ok ? "success" : await response.text(),
    };
  } catch (e) {
    steps.casesApiWithTechToken = { error: e.message };
  }

  // Step 5: Try calling Cases API with the USER's token (from gateway)
  const userToken = getUserToken(req);
  if (userToken) {
    try {
      const response = await fetch(
        `${IH_GATEWAY}/api/casemanagement/v3/cases?size=1`,
        { headers: { Authorization: `Bearer ${userToken}` } }
      );
      const responseHeaders = Object.fromEntries(response.headers.entries());
      steps.casesApiWithUserToken = {
        status: response.status,
        ok: response.ok,
        headers: responseHeaders,
        body: response.ok ? await response.json() : await response.text(),
      };
    } catch (e) {
      steps.casesApiWithUserToken = { error: e.message };
    }
  }

  res.json(steps);
});

// --- Post a comment on a case using the user's own bearer token ---
app.post("/api/cases/:handle/comments", async (req, res) => {
  const { handle } = req.params;
  const { description } = req.body;

  if (!description) {
    return res.status(400).json({ error: "description is required" });
  }

  // Step 1: Get the user's bearer token (passed by IH Gateway)
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "No bearer token from IH Gateway",
    });
  }
  const userToken = authHeader.slice(7);

  // Step 2: Create the case comment using the user's own token
  // The user token already has wom.techuser scope — no impersonation needed
  try {
    const comment = await createCaseComment(handle, description, userToken);
    res.json({ success: true, comment });
  } catch (e) {
    return res.status(502).json({
      error: "Failed to create case comment",
      detail: e.message,
    });
  }
});

// --- Helper to get user's bearer token from the gateway ---
function getUserToken(req) {
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  return null;
}

// --- List cases (so user can pick one) ---
app.get("/api/cases", async (req, res) => {
  const token = getUserToken(req);
  if (!token) {
    return res.status(401).json({ error: "No bearer token from IH Gateway" });
  }

  try {
    const response = await fetch(
      `${IH_GATEWAY}/api/casemanagement/v3/cases?size=20&sort=createdDate,desc`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(502).json({ error: "Failed to fetch cases", detail: e.message });
  }
});

// --- Get comments for a case ---
app.get("/api/cases/:handle/comments", async (req, res) => {
  const { handle } = req.params;
  const token = getUserToken(req);
  if (!token) {
    return res.status(401).json({ error: "No bearer token from IH Gateway" });
  }

  try {
    const response = await fetch(
      `${IH_GATEWAY}/api/casemanagement/v3/cases/${handle}/comments`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(502).json({
      error: "Failed to fetch comments",
      detail: e.message,
    });
  }
});

// =============================================================================
// Helper functions
// =============================================================================

function parseCookies(cookieStr) {
  const cookies = {};
  if (!cookieStr) return cookies;
  cookieStr.split(";").forEach((pair) => {
    const [key, ...val] = pair.trim().split("=");
    if (key) cookies[key] = val.join("=");
  });
  return cookies;
}

function extractUserInfo(req) {
  // Strategy 1: Decode the bearer token from Authorization header
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ")) {
    try {
      const decoded = jwt.decode(authHeader.slice(7));
      if (decoded) {
        // Try various claim names for email
        const email =
          decoded.email ||
          decoded.user_name ||
          decoded.preferred_username ||
          decoded.sub ||
          null;
        if (email && email.includes("@")) {
          return {
            email,
            source: "bearer_token",
            allClaims: decoded,
          };
        }
        // Even if no email, return what we have for debugging
        return {
          email: null,
          source: "bearer_token_no_email",
          allClaims: decoded,
        };
      }
    } catch (e) {
      // Fall through to other strategies
    }
  }

  // Strategy 2: Check for X-Forwarded-User or similar gateway headers
  const forwardedUser =
    req.headers["x-forwarded-user"] ||
    req.headers["x-user-email"] ||
    req.headers["x-auth-user"];
  if (forwardedUser) {
    return { email: forwardedUser, source: "forwarded_header" };
  }

  // Strategy 3: Check query params (some gateways pass identity this way)
  if (req.query.user_email) {
    return { email: req.query.user_email, source: "query_param" };
  }

  return null;
}

async function getTechnicalToken() {
  if (!IH_CLIENT_ID || !IH_CLIENT_SECRET) {
    throw new Error(
      "IH_CLIENT_ID and IH_CLIENT_SECRET must be set in environment"
    );
  }

  const auth = Buffer.from(`${IH_CLIENT_ID}:${IH_CLIENT_SECRET}`).toString(
    "base64"
  );

  const body = {
    appName: IH_APP_NAME,
    appVersion: IH_APP_VERSION,
    hostTenant: IH_TENANT,
    userTenant: IH_TENANT,
  };

  const response = await fetch(
    `${IH_GATEWAY}/api/technicaltokenmanager/v3/oauth/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SPACE-AUTH-KEY": `Basic ${auth}`,
      },
      body: JSON.stringify(body),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token request failed (${response.status}): ${text}`);
  }

  const data = await response.json();
  return data.access_token;
}

async function getImpersonatedToken(userInfo) {
  if (!userInfo.email) {
    throw new Error("No user email available for impersonation");
  }

  if (!IH_CLIENT_ID || !IH_CLIENT_SECRET) {
    throw new Error(
      "IH_CLIENT_ID and IH_CLIENT_SECRET must be set in environment"
    );
  }

  const auth = Buffer.from(`${IH_CLIENT_ID}:${IH_CLIENT_SECRET}`).toString(
    "base64"
  );

  const body = {
    appName: IH_APP_NAME,
    appVersion: IH_APP_VERSION,
    hostTenant: IH_TENANT,
    userTenant: IH_TENANT,
    caller_context_type: "email",
    caller_context: userInfo.email,
  };

  const response = await fetch(
    `${IH_GATEWAY}/api/technicaltokenmanager/v3/oauth/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-SPACE-AUTH-KEY": `Basic ${auth}`,
      },
      body: JSON.stringify(body),
    }
  );

  if (!response.ok) {
    const text = await response.text();
    throw new Error(
      `Impersonated token request failed (${response.status}): ${text}`
    );
  }

  const data = await response.json();
  return data.access_token;
}

async function createCaseComment(handle, description, token) {
  const url = `${IH_GATEWAY}/api/casemanagement/v3/cases/${handle}/comments`;
  console.log(`[createCaseComment] POST ${url}`);
  console.log(`[createCaseComment] Token starts with: ${token.substring(0, 20)}...`);

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      isActive: true,
      isResolution: false,
      description,
    }),
  });

  const responseHeaders = Object.fromEntries(response.headers.entries());
  console.log(`[createCaseComment] Response: ${response.status}`, responseHeaders);

  if (!response.ok) {
    const text = await response.text();
    console.log(`[createCaseComment] Error body: ${text}`);
    throw new Error(
      `Case comment failed (${response.status}): ${text} | Headers: ${JSON.stringify(responseHeaders)}`
    );
  }

  return response.json();
}

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Self-hosted IH app running on port ${PORT}`);
  console.log(`Tenant: ${IH_TENANT}`);
  console.log(`App credentials configured: ${!!IH_CLIENT_ID}`);
});
