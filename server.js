require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");

const required = ["DATABASE_URL", "JWT_SECRET", "ADMIN_PASSWORD"];
for (const key of required) if (!process.env[key]) {
  console.error(`Missing required environment variable: ${key}`); process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters."); process.exit(1);
}
const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }
});
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "4mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const translateLimiter = rateLimit({ windowMs: 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false });
const reviewLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const LANGS = ["az", "tr", "ru", "en"];
const username = process.env.ADMIN_USERNAME || "admin";
const passwordHashPromise = bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
const cookieOptions = {
  httpOnly: true, secure: process.env.NODE_ENV === "production",
  sameSite: "strict", path: "/", maxAge: 8 * 60 * 60 * 1000
};
function auth(req, res, next) {
  const token = req.cookies.ayan_admin;
  if (!token) return res.status(401).json({ error: "Giriş tələb olunur." });
  try { req.admin = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.clearCookie("ayan_admin", cookieOptions); return res.status(401).json({ error: "Sessiya bitib. Yenidən daxil olun." }); }
}
function flag(value, fallback = false) {
  if (value === true || value === "true" || value === "t" || value === 1) return true;
  if (value === false || value === "false" || value === "f" || value === 0) return false;
  return fallback;
}
function permissionView(row) {
  return {
    products: flag(row.can_products, true),
    categories: flag(row.can_categories, true),
    qr: flag(row.can_qr, false),
    billing: flag(row.can_billing, false)
  };
}
async function staffPermissions(name) {
  const result = await pool.query("SELECT can_products, can_categories, can_qr, can_billing FROM staff WHERE username=$1", [name]);
  if (!result.rowCount) return { products: false, categories: false, qr: false, billing: false };
  return permissionView(result.rows[0]);
}
function allow(area) {
  return async (req, res, next) => {
    if (req.admin.role !== "staff") return next();
    try {
      const perms = await staffPermissions(req.admin.sub);
      if (!perms[area]) return res.status(403).json({ error: "Bu bölmə üçün icazəniz yoxdur." });
      next();
    } catch (error) { console.error(error); res.status(500).json({ error: "İcazə yoxlanılmadı." }); }
  };
}
function requireAdmin(req, res, next) {
  if (req.admin.role === "staff") return res.status(403).json({ error: "Bu bölmə yalnız admin üçündür." });
  next();
}
function accountName(value) {
  const name = text(value, 40);
  return /^[\p{L}0-9._-]{3,40}$/u.test(name) ? name : "";
}
const INFO_KEYS = ["phone", "address", "hours", "wifi"];
async function readPlaceInfo() {
  const info = { phone: "", address: "", hours: "", wifi: "" };
  const rows = await pool.query("SELECT key_name, value FROM settings");
  for (const row of rows.rows) if (INFO_KEYS.includes(row.key_name)) info[row.key_name] = row.value || "";
  return info;
}
async function adminHash() {
  const saved = await pool.query("SELECT value FROM settings WHERE key_name=$1", ["admin_password_hash"]);
  if (saved.rowCount && saved.rows[0].value) return saved.rows[0].value;
  return passwordHashPromise;
}
function text(v, max=500) { return String(v ?? "").trim().slice(0,max); }
function storedImage(b) {
  if (!Object.prototype.hasOwnProperty.call(b, "image_base64")) return undefined;
  const raw = String(b.image_base64 ?? "").replace(/\s/g, "");
  if (!raw) return { data: "", mime: "" };
  const mime = text(b.image_mime, 40);
  if (!["image/jpeg", "image/png", "image/webp"].includes(mime)) throw new Error("Şəkil JPEG, PNG və ya WEBP olmalıdır.");
  if (raw.length > 2800000 || !/^[A-Za-z0-9+/=]+$/.test(raw)) throw new Error("Şəkil çox böyükdür və ya düzgün deyil.");
  return { data: raw, mime };
}
function presentProduct(row) {
  if (!row) return row;
  const copy = { ...row };
  const has = Boolean(copy.image_data) || copy.has_image === true || copy.has_image === 1 || copy.has_image === "t";
  delete copy.image_data;
  delete copy.image_mime;
  delete copy.has_image;
  if (has) copy.image_url = `/api/images/${copy.id}`;
  copy.is_spicy = flag(copy.is_spicy);
  copy.is_vegetarian = flag(copy.is_vegetarian);
  copy.has_nuts = flag(copy.has_nuts);
  return copy;
}
async function googleTranslate(url) {
  const response = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0", "Accept": "*/*" },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) throw new Error("Google status " + response.status);
  const data = await response.json();
  const out = (data[0] || []).map((part) => part && part[0]).join("").trim();
  if (!out) throw new Error("Google boş cavab qaytardı.");
  return out.slice(0, 1000);
}
async function memoryTranslate(value, source, target) {
  const memory = "https://api.mymemory.translated.net/get?q=" + encodeURIComponent(value) + "&langpair=" + encodeURIComponent(source + "|" + target);
  const response = await fetch(memory, { signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error("MyMemory status " + response.status);
  const data = await response.json();
  const out = data.responseData && data.responseData.translatedText;
  if (!out || /INVALID|QUERY LENGTH|MYMEMORY WARNING/i.test(out)) throw new Error("MyMemory limit.");
  return String(out).slice(0, 1000);
}
async function translateLine(value, source, target) {
  const q = encodeURIComponent(value);
  const pair = "sl=" + encodeURIComponent(source) + "&tl=" + encodeURIComponent(target) + "&dt=t&q=" + q;
  const attempts = [
    () => googleTranslate("https://translate.googleapis.com/translate_a/single?client=gtx&" + pair),
    () => googleTranslate("https://clients5.google.com/translate_a/single?client=dict-chrome-ex&" + pair),
    () => memoryTranslate(value, source, target)
  ];
  let last = new Error("Tərcümə alınmadı.");
  for (const attempt of attempts) {
    try { return await attempt(); }
    catch (error) { last = error; console.error("Translate attempt failed", source, target, error.message); }
  }
  throw last;
}
function productInput(b) {
  const price = Number(b.price);
  if (!Number.isFinite(price) || price < 0) throw new Error("Qiymət düzgün deyil.");
  if (!text(b.name_az,180)) throw new Error("Məhsulun AZ adı mütləqdir.");
  const image = text(b.image_url,1500);
  if (image && !/^https:\/\/|^http:\/\//i.test(image)) throw new Error("Şəkil ünvanı http:// və ya https:// ilə başlamalıdır.");
  return {
    category_id: b.category_id ? Number(b.category_id) : null, price,
    image_url:image, image: storedImage(b), name_az:text(b.name_az,180), name_tr:text(b.name_tr,180),
    name_ru:text(b.name_ru,180), name_en:text(b.name_en,180),
    desc_az:text(b.desc_az,1000), desc_tr:text(b.desc_tr,1000),
    desc_ru:text(b.desc_ru,1000), desc_en:text(b.desc_en,1000),
    is_active: b.is_active !== false,
    is_spicy: flag(b.is_spicy), is_vegetarian: flag(b.is_vegetarian), has_nuts: flag(b.has_nuts)
  };
}
app.get("/api/health", async (req,res) => {
  try { await pool.query("SELECT 1"); res.json({ok:true,database:"connected"}); }
  catch { res.status(503).json({ok:false,database:"unavailable"}); }
});
const MONTH_MS = 30 * 24 * 60 * 60 * 1000;
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;
function billingView(row) {
  const until = new Date(row.paid_until);
  return { paid_until: until.toISOString(), locked: until.getTime() <= Date.now(), days_left: Math.max(0, Math.ceil((until.getTime() - Date.now()) / 86400000)) };
}
async function ensureBilling() {
  const existing = await pool.query("SELECT id, paid_until FROM billing ORDER BY id LIMIT 1");
  if (existing.rowCount) return existing.rows[0];
  const until = new Date(Date.now() + MONTH_MS);
  const inserted = await pool.query("INSERT INTO billing(paid_until) VALUES ($1) RETURNING id, paid_until", [until]);
  return inserted.rows[0];
}
app.get("/api/menu", async (req,res) => {
  try {
    const bill = billingView(await ensureBilling());
    const info = await readPlaceInfo();
    if (bill.locked) {
      res.set("Cache-Control", "no-store");
      return res.json({ locked: true, paid_until: bill.paid_until, categories: [], products: [], info });
    }
    const [cats,prods] = await Promise.all([
      pool.query("SELECT id,name_az,name_tr,name_ru,name_en,sort_order FROM categories ORDER BY sort_order,id"),
      pool.query("SELECT id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_spicy,is_vegetarian,has_nuts FROM products WHERE is_active=TRUE ORDER BY sort_order,id")
    ]);
    const reviewRows = await pool.query("SELECT product_id, stars, comment, created_at FROM reviews ORDER BY created_at DESC");
    res.set("Cache-Control","no-store");
    res.json({categories:cats.rows,products:withRatings(prods.rows.map(presentProduct), reviewRows.rows),info});
  } catch(e) { console.error(e); res.status(500).json({error:"Menyu yüklənmədi."}); }
});
app.post("/api/admin/login", loginLimiter, async (req,res) => {
  const user = text(req.body.username,40);
  const pass = String(req.body.password ?? "");
  try {
    if (user.toLowerCase() === username.toLowerCase()) {
      if (!(await bcrypt.compare(pass, await adminHash()))) return res.status(401).json({error:"İstifadəçi adı və ya şifrə yanlışdır."});
      const token = jwt.sign({sub:username,role:"admin"},process.env.JWT_SECRET,{expiresIn:"8h"});
      return res.cookie("ayan_admin",token,cookieOptions).json({ok:true,username,role:"admin"});
    }
    const staff = await pool.query("SELECT username, password_hash FROM staff WHERE LOWER(username)=LOWER($1)", [user]);
    const row = staff.rows[0];
    if (!row || !(await bcrypt.compare(pass, row.password_hash))) return res.status(401).json({error:"İstifadəçi adı və ya şifrə yanlışdır."});
    const token = jwt.sign({sub:row.username,role:"staff"},process.env.JWT_SECRET,{expiresIn:"8h"});
    res.cookie("ayan_admin",token,cookieOptions).json({ok:true,username:row.username,role:"staff"});
  } catch (error) { console.error(error); res.status(500).json({ error: "Giriş alınmadı." }); }
});
app.post("/api/admin/logout",(req,res)=>{res.clearCookie("ayan_admin",cookieOptions).json({ok:true});});
app.get("/api/admin/me", auth, async (req, res) => {
  const role = req.admin.role === "staff" ? "staff" : "admin";
  try {
    const permissions = role === "staff" ? await staffPermissions(req.admin.sub) : { products: true, categories: true, qr: true, billing: true };
    res.json({ ok: true, username: req.admin.sub, role, permissions });
  } catch (error) { console.error(error); res.status(500).json({ error: "Sessiya yoxlanılmadı." }); }
});
app.post("/api/admin/translate", translateLimiter, auth, async (req, res) => {
  if (req.admin.role === "staff") {
    const perms = await staffPermissions(req.admin.sub);
    if (!perms.products && !perms.categories) return res.status(403).json({ error: "Bu bölmə üçün icazəniz yoxdur." });
  }
  const value = text(req.body.text, 1000);
  const source = text(req.body.source, 2);
  if (!value || !LANGS.includes(source)) return res.status(400).json({ error: "Tərcümə üçün mətn lazımdır." });
  const translations = { [source]: value };
  for (const code of LANGS.filter((item) => item !== source)) {
    try { translations[code] = await translateLine(value, source, code); }
    catch (error) { console.error(error); }
  }
  if (Object.keys(translations).length < 2) return res.status(502).json({ error: "Avtomatik tərcümə alınmadı. Digər dilləri əl ilə yaza bilərsiniz." });
  res.json({ translations });
});
app.get("/api/images/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT image_data, image_mime FROM products WHERE id=$1", [Number(req.params.id)]);
    const row = result.rows[0];
    if (!row || !row.image_data) return res.status(404).end();
    res.set("Content-Type", row.image_mime || "image/jpeg");
    res.set("Cache-Control", "public, max-age=86400");
    res.send(Buffer.from(row.image_data, "base64"));
  } catch (error) { console.error(error); res.status(404).end(); }
});
function withRatings(products, rows) {
  const grouped = new Map();
  for (const row of rows) {
    const id = String(row.product_id);
    if (!grouped.has(id)) grouped.set(id, []);
    grouped.get(id).push(row);
  }
  return products.map((product) => {
    const list = grouped.get(String(product.id)) || [];
    const count = list.length;
    const avg = count ? Math.round((list.reduce((sum, row) => sum + Number(row.stars), 0) / count) * 10) / 10 : 0;
    return {
      ...product,
      rating_avg: avg,
      rating_count: count,
      reviews: list.filter((row) => row.comment).slice(0, 3).map((row) => ({ stars: Number(row.stars), comment: row.comment }))
    };
  });
}
app.post("/api/reviews", reviewLimiter, async (req, res) => {
  try {
    const bill = billingView(await ensureBilling());
    if (bill.locked) return res.status(403).json({ error: "Menyu bağlıdır." });
    const productId = Number(req.body.product_id);
    const stars = Number(req.body.stars);
    const comment = text(req.body.comment, 400);
    const guest = text(req.body.guest_key, 80);
    if (!Number.isInteger(productId) || productId <= 0) return res.status(400).json({ error: "Yemək tapılmadı." });
    if (!Number.isInteger(stars) || stars < 1 || stars > 5) return res.status(400).json({ error: "1-dən 5-ə qədər ulduz seçin." });
    if (!/^[a-zA-Z0-9-]{16,80}$/.test(guest)) return res.status(400).json({ error: "Rəy göndərilmədi." });
    const product = await pool.query("SELECT id FROM products WHERE id=$1 AND is_active=TRUE", [productId]);
    if (!product.rowCount) return res.status(404).json({ error: "Yemək tapılmadı." });
    await pool.query("DELETE FROM reviews WHERE product_id=$1", [productId]);
    await pool.query("INSERT INTO reviews(product_id, stars, comment, guest_key) VALUES ($1,$2,$3,$4)", [productId, stars, comment, guest]);
    const summary = await pool.query("SELECT product_id, stars, comment FROM reviews WHERE product_id=$1 ORDER BY created_at DESC", [productId]);
    const rated = withRatings([{ id: productId }], summary.rows)[0];
    res.json({ rating_avg: rated.rating_avg, rating_count: rated.rating_count, reviews: rated.reviews });
  } catch (error) { console.error(error); res.status(500).json({ error: "Rəy göndərilmədi." }); }
});
app.get("/api/admin/reviews", auth, allow("products"), async (req, res) => {
  try {
    const result = await pool.query("SELECT r.id, r.stars, r.comment, r.created_at, p.name_az FROM reviews r LEFT JOIN products p ON p.id=r.product_id ORDER BY r.created_at DESC LIMIT 100");
    res.json(result.rows);
  } catch (error) { console.error(error); res.status(500).json({ error: "Rəylər yüklənmədi." }); }
});
app.delete("/api/admin/reviews/:id", auth, allow("products"), async (req, res) => {
  try {
    await pool.query("DELETE FROM reviews WHERE id=$1", [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Rəy silinmədi." }); }
});
app.get("/api/admin/info", auth, requireAdmin, async (req, res) => {
  try { res.json(await readPlaceInfo()); }
  catch (error) { console.error(error); res.status(500).json({ error: "Məlumatlar açılmadı." }); }
});
app.put("/api/admin/info", auth, requireAdmin, async (req, res) => {
  try {
    for (const key of INFO_KEYS) {
      const value = text(req.body[key], 180);
      const existing = await pool.query("SELECT id FROM settings WHERE key_name=$1", [key]);
      if (existing.rowCount) await pool.query("UPDATE settings SET value=$1 WHERE id=$2", [value, existing.rows[0].id]);
      else await pool.query("INSERT INTO settings(key_name, value) VALUES ($1,$2)", [key, value]);
    }
    res.json(await readPlaceInfo());
  } catch (error) { console.error(error); res.status(500).json({ error: "Məlumatlar saxlanılmadı." }); }
});
app.post("/api/admin/password", auth, requireAdmin, async (req, res) => {
  const current = String(req.body.current ?? "");
  const next = String(req.body.next ?? "");
  if (next.length < 8) return res.status(400).json({ error: "Yeni şifrə ən azı 8 simvol olmalıdır." });
  try {
    if (!(await bcrypt.compare(current, await adminHash()))) return res.status(400).json({ error: "Cari şifrə yanlışdır." });
    const nextHash = await bcrypt.hash(next, 12);
    const existing = await pool.query("SELECT id FROM settings WHERE key_name=$1", ["admin_password_hash"]);
    if (existing.rowCount) await pool.query("UPDATE settings SET value=$1 WHERE key_name=$2", [nextHash, "admin_password_hash"]);
    else await pool.query("INSERT INTO settings(key_name, value) VALUES ($1,$2)", ["admin_password_hash", nextHash]);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Şifrə dəyişmədi." }); }
});
app.get("/api/admin/staff", auth, requireAdmin, async (req, res) => {
  try {
    const rows = await pool.query("SELECT id, username, can_products, can_categories, can_qr, can_billing FROM staff ORDER BY id");
    res.json(rows.rows.map((row) => ({ id: row.id, username: row.username, ...permissionView(row) })));
  } catch (error) { console.error(error); res.status(500).json({ error: "İşçilər yüklənmədi." }); }
});
app.post("/api/admin/staff", auth, requireAdmin, async (req, res) => {
  const name = accountName(req.body.username);
  const pass = String(req.body.password ?? "");
  if (!name) return res.status(400).json({ error: "İşçi adı 3-40 simvol olmalıdır və yalnız hərf, rəqəm, nöqtə, tire istifadə edin." });
  if (name.toLowerCase() === username.toLowerCase()) return res.status(400).json({ error: "Bu ad admin üçündür." });
  if (pass.length < 8) return res.status(400).json({ error: "İşçi şifrəsi ən azı 8 simvol olmalıdır." });
  try {
    const taken = await pool.query("SELECT id FROM staff WHERE LOWER(username)=LOWER($1)", [name]);
    if (taken.rowCount) return res.status(400).json({ error: "Bu işçi adı artıq var." });
    const permissions = permissionView({
      can_products: req.body.products, can_categories: req.body.categories,
      can_qr: req.body.qr, can_billing: req.body.billing
    });
    const created = await pool.query("INSERT INTO staff(username, password_hash, can_products, can_categories, can_qr, can_billing) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, can_products, can_categories, can_qr, can_billing", [name, await bcrypt.hash(pass, 12), permissions.products, permissions.categories, permissions.qr, permissions.billing]);
    res.status(201).json({ id: created.rows[0].id, username: created.rows[0].username, ...permissionView(created.rows[0]) });
  } catch (error) { console.error(error); res.status(500).json({ error: "İşçi əlavə olunmadı." }); }
});
app.put("/api/admin/staff/:id", auth, requireAdmin, async (req, res) => {
  const permissions = permissionView({
    can_products: req.body.products, can_categories: req.body.categories,
    can_qr: req.body.qr, can_billing: req.body.billing
  });
  try {
    const updated = await pool.query("UPDATE staff SET can_products=$1, can_categories=$2, can_qr=$3, can_billing=$4 WHERE id=$5 RETURNING id, username, can_products, can_categories, can_qr, can_billing", [permissions.products, permissions.categories, permissions.qr, permissions.billing, Number(req.params.id)]);
    if (!updated.rowCount) return res.status(404).json({ error: "İşçi tapılmadı." });
    res.json({ id: updated.rows[0].id, username: updated.rows[0].username, ...permissionView(updated.rows[0]) });
  } catch (error) { console.error(error); res.status(500).json({ error: "İcazə saxlanılmadı." }); }
});
app.delete("/api/admin/staff/:id", auth, requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM staff WHERE id=$1", [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "İşçi silinmədi." }); }
});
app.get("/api/admin/billing", auth, allow("billing"), async (req, res) => {
  try { res.json(billingView(await ensureBilling())); }
  catch (error) { console.error(error); res.status(500).json({ error: "Ödəniş məlumatı açılmadı." }); }
});
app.post("/api/admin/billing/activate", auth, allow("billing"), async (req, res) => {
  try {
    const row = await ensureBilling();
    const plan = req.body && req.body.plan === "year" ? "year" : "month";
    const until = new Date(Date.now() + (plan === "year" ? YEAR_MS : MONTH_MS));
    await pool.query("UPDATE billing SET paid_until=$1 WHERE id=$2", [until, row.id]);
    res.json(billingView({ paid_until: until }));
  } catch (error) { console.error(error); res.status(500).json({ error: "Menyu aktiv edilmədi." }); }
});
app.get("/api/admin/menu",auth,async(req,res)=>{
  try {
    const [cats,prods]=await Promise.all([
      pool.query("SELECT * FROM categories ORDER BY sort_order,id"),
      pool.query("SELECT id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active,is_spicy,is_vegetarian,has_nuts,sort_order FROM products ORDER BY sort_order,id")
    ]);
    res.json({categories:cats.rows,products:prods.rows.map(presentProduct)});
  } catch(e){console.error(e);res.status(500).json({error:"Məlumatlar yüklənmədi."});}
});
async function nextSort(table) {
  const result = await pool.query(`SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM ${table}`);
  return result.rows[0].n;
}
app.put("/api/admin/order", auth, async (req, res) => {
  const table = req.body.kind === "categories" ? "categories" : req.body.kind === "products" ? "products" : "";
  if (req.admin.role === "staff") {
    const perms = await staffPermissions(req.admin.sub);
    if ((table === "products" && !perms.products) || (table === "categories" && !perms.categories)) return res.status(403).json({ error: "Bu bölmə üçün icazəniz yoxdur." });
  }
  const ids = Array.isArray(req.body.ids) ? req.body.ids.map(Number).filter((id) => Number.isInteger(id) && id > 0) : [];
  if (!table || !ids.length) return res.status(400).json({ error: "Sıra yenilənmədi." });
  try {
    for (let index = 0; index < ids.length; index++) await pool.query(`UPDATE ${table} SET sort_order=$1 WHERE id=$2`, [index + 1, ids[index]]);
    res.json({ ok: true });
  } catch (error) { console.error(error); res.status(500).json({ error: "Sıra yenilənmədi." }); }
});
app.post("/api/admin/categories",auth,allow("categories"),async(req,res)=>{
  const az=text(req.body.name_az,180);
  if(!az)return res.status(400).json({error:"Kateqoriya adı tələb olunur."});
  try {
    const order = await nextSort("categories");
    const r=await pool.query("INSERT INTO categories(name_az,name_tr,name_ru,name_en,sort_order) VALUES($1,$2,$3,$4,$5) RETURNING *",[az,text(req.body.name_tr,180),text(req.body.name_ru,180),text(req.body.name_en,180),order]);
    res.status(201).json(r.rows[0]);
  } catch(e){console.error(e);res.status(500).json({error:"Kateqoriya yaradıla bilmədi."});}
});
app.put("/api/admin/categories/:id",auth,allow("categories"),async(req,res)=>{
  try{
    const r=await pool.query("UPDATE categories SET name_az=$1,name_tr=$2,name_ru=$3,name_en=$4 WHERE id=$5 RETURNING *",[text(req.body.name_az,180),text(req.body.name_tr,180),text(req.body.name_ru,180),text(req.body.name_en,180),Number(req.params.id)]);
    if(!r.rowCount)return res.status(404).json({error:"Kateqoriya tapılmadı."});res.json(r.rows[0]);
  }catch(e){console.error(e);res.status(500).json({error:"Kateqoriya yenilənmədi."});}
});
app.delete("/api/admin/categories/:id",auth,allow("categories"),async(req,res)=>{
  try{const r=await pool.query("DELETE FROM categories WHERE id=$1 RETURNING id",[Number(req.params.id)]);if(!r.rowCount)return res.status(404).json({error:"Tapılmadı."});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"Kateqoriya silinmədi."});}
});
app.patch("/api/admin/products/:id/active", auth, allow("products"), async (req, res) => {
  try {
    const r = await pool.query("UPDATE products SET is_active=$1, updated_at=NOW() WHERE id=$2 RETURNING id, is_active", [req.body.is_active === true, Number(req.params.id)]);
    if (!r.rowCount) return res.status(404).json({ error: "Məhsul tapılmadı." });
    res.json(r.rows[0]);
  } catch (error) { console.error(error); res.status(500).json({ error: "Məhsulun vəziyyəti dəyişmədi." }); }
});
app.post("/api/admin/products",auth,allow("products"),async(req,res)=>{
  try{
    const p=productInput(req.body);
    const image = p.image || { data: "", mime: "" };
    const imageUrl = image.data ? "" : p.image_url;
    const order = await nextSort("products");
    const r=await pool.query(`INSERT INTO products(category_id,price,image_url,image_data,image_mime,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active,is_spicy,is_vegetarian,has_nuts,sort_order)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active,is_spicy,is_vegetarian,has_nuts`,
      [p.category_id,p.price,imageUrl,image.data,image.mime,p.name_az,p.name_tr,p.name_ru,p.name_en,p.desc_az,p.desc_tr,p.desc_ru,p.desc_en,p.is_active,p.is_spicy,p.is_vegetarian,p.has_nuts,order]);
    res.status(201).json(presentProduct(r.rows[0]));
  }catch(e){res.status(400).json({error:e.message||"Məhsul əlavə olunmadı."});}
});
app.put("/api/admin/products/:id",auth,allow("products"),async(req,res)=>{
  try{
    const p=productInput(req.body);
    const imageSql = p.image ? ",image_url=$16,image_data=$17,image_mime=$18" : "";
    const params = [p.category_id,p.price,p.name_az,p.name_tr,p.name_ru,p.name_en,p.desc_az,p.desc_tr,p.desc_ru,p.desc_en,p.is_active,p.is_spicy,p.is_vegetarian,p.has_nuts,Number(req.params.id)];
    if (p.image) params.push(p.image.data ? "" : p.image_url, p.image.data, p.image.mime);
    const r=await pool.query(`UPDATE products SET category_id=$1,price=$2,name_az=$3,name_tr=$4,name_ru=$5,name_en=$6,desc_az=$7,desc_tr=$8,desc_ru=$9,desc_en=$10,is_active=$11,is_spicy=$12,is_vegetarian=$13,has_nuts=$14,updated_at=NOW()${imageSql} WHERE id=$15 RETURNING id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active,is_spicy,is_vegetarian,has_nuts`, params);
    if(!r.rowCount)return res.status(404).json({error:"Məhsul tapılmadı."});res.json(presentProduct(r.rows[0]));
  }catch(e){res.status(400).json({error:e.message||"Məhsul yenilənmədi."});}
});
app.delete("/api/admin/products/:id",auth,allow("products"),async(req,res)=>{
  try{const r=await pool.query("DELETE FROM products WHERE id=$1 RETURNING id",[Number(req.params.id)]);if(!r.rowCount)return res.status(404).json({error:"Məhsul tapılmadı."});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"Məhsul silinmədi."});}
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=Number(process.env.PORT||3000);
(async()=>{
  try{
    await pool.query("SELECT 1");
    const schema=require("fs").readFileSync(path.join(__dirname,"db","schema.sql"),"utf8");
    await pool.query(schema);
    const count=await pool.query("SELECT COUNT(*)::int AS n FROM categories");
    if(count.rows[0].n===0){
      await pool.query(`INSERT INTO categories(name_az,name_tr,name_ru,name_en,sort_order) VALUES
        ('Səhər yeməyi','Kahvaltı','Завтраки','Breakfast',1),('Salatlar','Salatalar','Салаты','Salads',2),
        ('İsti yeməklər','Ana yemekler','Горячие блюда','Main courses',3),('İçkilər','İçecekler','Напитки','Drinks',4),('Desertlər','Tatlılar','Десерты','Desserts',5)`);
    }
    await pool.query(`UPDATE categories SET name_tr = CASE name_az
      WHEN 'Səhər yeməyi' THEN 'Kahvaltı'
      WHEN 'Salatlar' THEN 'Salatalar'
      WHEN 'İsti yeməklər' THEN 'Ana yemekler'
      WHEN 'İçkilər' THEN 'İçecekler'
      WHEN 'Desertlər' THEN 'Tatlılar'
      ELSE name_tr END
      WHERE COALESCE(name_tr,'') = ''`);
    app.listen(port,()=>console.log(`Ayan Palace server listening on ${port}`));
  }catch(e){console.error("Startup/database error:",e);process.exit(1);}
})();
