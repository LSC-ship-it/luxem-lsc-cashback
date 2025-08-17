// api/shopify-orders-paid.js  (Vercel Node API)
import crypto from "crypto";
import { sql } from "@vercel/postgres";

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const ALLOWED_SHOPIFY_DOMAIN = (process.env.ALLOWED_SHOPIFY_DOMAIN || "").toLowerCase();
const LSC_CASHBACK_PERCENT = Number(process.env.LSC_CASHBACK_PERCENT || 5);

let tableReady = false;
async function ensureTable() {
  if (tableReady) return;
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
    );
    CREATE INDEX IF NOT EXISTS idx_lsc_cashback_email ON lsc_cashback_events (customer_email);
    CREATE INDEX IF NOT EXISTS idx_lsc_cashback_created ON lsc_cashback_events (created_at DESC);
  `;
  tableReady = true;
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function timingSafeEqualStr(a, b) {
  const A = Buffer.from(String(a), "utf8");
  const B = Buffer.from(String(b), "utf8");
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const raw = await readRawBody(req);
  const text = raw.toString("utf8");

  const hmac = req.headers["x-shopify-hmac-sha256"] || "";
  const shop = String(req.headers["x-shopify-shop-domain"] || "").toLowerCase();
  const topic = String(req.headers["x-shopify-topic"] || "").toLowerCase();

  if (!ALLOWED_SHOPIFY_DOMAIN || shop !== ALLOWED_SHOPIFY_DOMAIN) {
    return res.status(403).send("Forbidden (domain)");
  }

  if (!SHOPIFY_WEBHOOK_SECRET) return res.status(500).send("Server misconfigured (secret)");
  const digest = crypto.createHmac("sha256", SHOPIFY_WEBHOOK_SECRET).update(raw).digest("base64");
  if (!timingSafeEqualStr(digest, hmac)) return res.status(403).send("Forbidden (hmac)");

  if (topic !== "orders/paid") return res.status(200).send("Ignored topic");

  let payload;
  try { payload = JSON.parse(text); } catch { return res.status(400).send("Bad JSON"); }

  const orderId = String(payload.id || "");
  const customerEmail = payload?.email || payload?.customer?.email || null;
  const currency =
    payload?.total_price_set?.shop_money?.currency_code ||
    payload?.currency || payload?.presentment_currency || "USD";
  const totalPaid = Number(payload?.total_price_set?.shop_money?.amount ?? payload?.total_price ?? 0);
  if (!orderId || !(totalPaid > 0)) return res.status(200).send("Missing order data");

  const pct = isFinite(LSC_CASHBACK_PERCENT) ? LSC_CASHBACK_PERCENT : 5;
  const cashbackAmount = Number((totalPaid * (pct / 100)).toFixed(2));

  try {
    await ensureTable();
    await sql/* sql */`
      INSERT INTO lsc_cashback_events (
        order_id, shop_domain, customer_email, currency, total_paid, cashback_percent, cashback_amount, raw
      )
      VALUES (
        ${orderId}, ${shop}, ${customerEmail}, ${currency}, ${totalPaid}, ${pct}, ${cashbackAmount}, ${payload}
      )
      ON CONFLICT (order_id) DO NOTHING;
    `;
  } catch (e) {
    console.error("DB insert error:", e);
  }

  console.log("[LSC] orders/paid", { shop, orderId, currency, totalPaid, pct, cashbackAmount });
  return res.status(200).send("OK");
}
