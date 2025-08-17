// api/shopify-orders-paid.js  (Vercel Node API)
import crypto from "crypto";
import { sql } from "@vercel/postgres";

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const ALLOWED_SHOPIFY_DOMAIN = (process.env.ALLOWED_SHOPIFY_DOMAIN || "").toLowerCase();
const LSC_CASHBACK_PERCENT = Number(process.env.LSC_CASHBACK_PERCENT || 5);

let tableReady = false;
async function ensureTable() {
  if (tableReady) return;

  // IMPORTANT: one statement per call (Neon disallows multiple commands)
  await sql/* sql */`
    CREATE TABLE IF NOT EXISTS lsc_cashback_events (
      order_id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      shop_domain TEXT NOT NULL,
      customer_email TEXT,
      currency TEXT NOT NULL,
      total_paid NUMERIC NOT NULL,
      cashback_percent NUMERIC NOT NULL,
      cashback_amount NUMERIC NOT NULL,
      raw JSONB
    )
  `;

  await sql/* sql */`
    CREATE INDEX IF NOT EXISTS idx_lsc_cashback_email
    ON lsc_cashback_events (customer_email)
  `;

  await sql/* sql */`
    CREATE INDEX IF NOT EXISTS idx_lsc_cashback_created
    ON lsc_cashback_events (created_at)
  `;

  tableReady = true;
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function verifyShopifyHmac(rawBody, hmacHeader) {
  if (!SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody, "utf8")
    .digest("base64");
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader || "", "utf8"));
}

export const config = {
  api: {
    bodyParser: false, // we need raw body for HMAC verification
  },
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method Not Allowed" });
  }

  try {
    const rawBody = await readRawBody(req);

    const hmacHeader = req.headers["x-shopify-hmac-sha256"];
    const topic = req.headers["x-shopify-topic"];
    const shopDomain = String(req.headers["x-shopify-shop-domain"] || "").toLowerCase();

    // (optional) restrict by shop domain
    if (ALLOWED_SHOPIFY_DOMAIN && shopDomain !== ALLOWED_SHOPIFY_DOMAIN) {
      return res.status(401).json({ ok: false, error: "Unauthorized shop domain" });
    }

    // verify HMAC
    if (!verifyShopifyHmac(rawBody, hmacHeader)) {
      return res.status(401).json({ ok: false, error: "Invalid HMAC" });
    }

    // parse JSON payload
    const payload = JSON.parse(rawBody.toString("utf8"));
    // Accept both Orders Paid & Payment events
    if (!topic || (!topic.includes("orders/paid") && !topic.includes("order"))) {
      // Not our event; acknowledge to avoid retries.
      return res.status(200).json({ ok: true, skipped: true, reason: "Not an orders/paid topic" });
    }

    // Extract values (fallbacks if missing)
    const orderId = String(payload?.id ?? payload?.order_id ?? "");
    const customerEmail =
      payload?.email || payload?.customer?.email || payload?.customer?.default_address?.email || null;
    const currency = payload?.currency || payload?.presentment_currency || "USD";

    // Shopify totals: total_price or current_total_price (string numbers)
    const totalPaidRaw =
      payload?.total_price ||
      payload?.current_total_price ||
      payload?.total_price_set?.shop_money?.amount ||
      "0";
    const totalPaid = Number(totalPaidRaw);

    const cashbackPercent = Number.isFinite(LSC_CASHBACK_PERCENT) ? LSC_CASHBACK_PERCENT : 5;
    const cashbackAmount = Number((totalPaid * (cashbackPercent / 100)).toFixed(2));

    await ensureTable();

    // SINGLE-STATEMENT INSERT (Neon-safe) + RETURNING
    const result = await sql/* sql */`
      INSERT INTO lsc_cashback_events
        (order_id, shop_domain, customer_email, currency,
         total_paid, cashback_percent, cashback_amount, raw)
      VALUES
        (${orderId}, ${shopDomain}, ${customerEmail}, ${currency},
         ${totalPaid}, ${cashbackPercent}, ${cashbackAmount}, ${payload})
      ON CONFLICT (order_id) DO UPDATE SET
        shop_domain = EXCLUDED.shop_domain,
        customer_email = EXCLUDED.customer_email,
        currency = EXCLUDED.currency,
        total_paid = EXCLUDED.total_paid,
        cashback_percent = EXCLUDED.cashback_percent,
        cashback_amount = EXCLUDED.cashback_amount,
        raw = EXCLUDED.raw
      RETURNING *
    `;

    console.log("Cashback saved:", {
      order_id: result.rows?.[0]?.order_id,
      cashback_amount: result.rows?.[0]?.cashback_amount,
    });

    // Always 200 so Shopify doesn't retry
    return res.status(200).json({ ok: true, order_id: orderId, cashback_amount: cashbackAmount });
  } catch (err) {
    console.error("Webhook error:", err?.message || err);
    // Still return 200 to avoid Shopify retries, but log for debugging
    return res.status(200).json({ ok: false, error: "Logged server error" });
  }
}
