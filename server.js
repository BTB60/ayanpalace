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
  return copy;
}
async function translateLine(value, source, target) {
  const google = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=" + encodeURIComponent(source) + "&tl=" + encodeURIComponent(target) + "&dt=t&q=" + encodeURIComponent(value);
  try {
    const response = await fetch(google);
    if (response.ok) {
      const data = await response.json();
      const out = (data[0] || []).map((part) => part && part[0]).join("").trim();
      if (out) return out.slice(0, 1000);
    }
  } catch (error) { console.error("Google translate failed", error); }
  const memory = "https://api.mymemory.translated.net/get?q=" + encodeURIComponent(value) + "&langpair=" + encodeURIComponent(source + "|" + target);
  const response = await fetch(memory);
  if (!response.ok) throw new Error("Tərcümə alınmadı.");
  const data = await response.json();
  const out = data.responseData && data.responseData.translatedText;
  if (!out || /INVALID|QUERY LENGTH|MYMEMORY WARNING/i.test(out)) throw new Error("Tərcümə alınmadı.");
  return String(out).slice(0, 1000);
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
    is_active: b.is_active !== false
  };
}
app.get("/api/health", async (req,res) => {
  try { await pool.query("SELECT 1"); res.json({ok:true,database:"connected"}); }
  catch { res.status(503).json({ok:false,database:"unavailable"}); }
});
app.get("/api/menu", async (req,res) => {
  try {
    const [cats,prods] = await Promise.all([
      pool.query("SELECT id,name_az,name_tr,name_ru,name_en,sort_order FROM categories ORDER BY sort_order,id"),
      pool.query("SELECT id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en FROM products WHERE is_active=TRUE ORDER BY sort_order,id")
    ]);
    res.set("Cache-Control","no-store");
    res.json({categories:cats.rows,products:prods.rows.map(presentProduct)});
  } catch(e) { console.error(e); res.status(500).json({error:"Menyu yüklənmədi."}); }
});
app.post("/api/admin/login", loginLimiter, async (req,res) => {
  const user = text(req.body.username,100);
  const pass = String(req.body.password ?? "");
  const hash = await passwordHashPromise;
  if (user !== username || !(await bcrypt.compare(pass,hash))) return res.status(401).json({error:"İstifadəçi adı və ya şifrə yanlışdır."});
  const token = jwt.sign({sub:username,role:"admin"},process.env.JWT_SECRET,{expiresIn:"8h"});
  res.cookie("ayan_admin",token,cookieOptions).json({ok:true,username});
});
app.post("/api/admin/logout",(req,res)=>{res.clearCookie("ayan_admin",cookieOptions).json({ok:true});});
app.get("/api/admin/me",auth,(req,res)=>res.json({ok:true,username:req.admin.sub}));
app.post("/api/admin/translate", translateLimiter, auth, async (req, res) => {
  const value = text(req.body.text, 1000);
  const source = text(req.body.source, 2);
  if (!value || !LANGS.includes(source)) return res.status(400).json({ error: "Tərcümə üçün mətn lazımdır." });
  try {
    const translations = { [source]: value };
    await Promise.all(LANGS.filter((code) => code !== source).map(async (code) => {
      translations[code] = await translateLine(value, source, code);
    }));
    res.json({ translations });
  } catch (error) {
    console.error(error);
    res.status(502).json({ error: "Avtomatik tərcümə alınmadı. Digər dilləri əl ilə yaza bilərsiniz." });
  }
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
app.get("/api/admin/menu",auth,async(req,res)=>{
  try {
    const [cats,prods]=await Promise.all([
      pool.query("SELECT * FROM categories ORDER BY sort_order,id"),
      pool.query("SELECT id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active,sort_order FROM products ORDER BY sort_order,id")
    ]);
    res.json({categories:cats.rows,products:prods.rows.map(presentProduct)});
  } catch(e){console.error(e);res.status(500).json({error:"Məlumatlar yüklənmədi."});}
});
app.post("/api/admin/categories",auth,async(req,res)=>{
  const az=text(req.body.name_az,180);
  if(!az)return res.status(400).json({error:"Kateqoriya adı tələb olunur."});
  try {
    const r=await pool.query("INSERT INTO categories(name_az,name_tr,name_ru,name_en) VALUES($1,$2,$3,$4) RETURNING *",[az,text(req.body.name_tr,180),text(req.body.name_ru,180),text(req.body.name_en,180)]);
    res.status(201).json(r.rows[0]);
  } catch(e){console.error(e);res.status(500).json({error:"Kateqoriya yaradıla bilmədi."});}
});
app.put("/api/admin/categories/:id",auth,async(req,res)=>{
  try{
    const r=await pool.query("UPDATE categories SET name_az=$1,name_tr=$2,name_ru=$3,name_en=$4 WHERE id=$5 RETURNING *",[text(req.body.name_az,180),text(req.body.name_tr,180),text(req.body.name_ru,180),text(req.body.name_en,180),Number(req.params.id)]);
    if(!r.rowCount)return res.status(404).json({error:"Kateqoriya tapılmadı."});res.json(r.rows[0]);
  }catch(e){console.error(e);res.status(500).json({error:"Kateqoriya yenilənmədi."});}
});
app.delete("/api/admin/categories/:id",auth,async(req,res)=>{
  try{const r=await pool.query("DELETE FROM categories WHERE id=$1 RETURNING id",[Number(req.params.id)]);if(!r.rowCount)return res.status(404).json({error:"Tapılmadı."});res.json({ok:true});}
  catch(e){console.error(e);res.status(500).json({error:"Kateqoriya silinmədi."});}
});
app.post("/api/admin/products",auth,async(req,res)=>{
  try{
    const p=productInput(req.body);
    const image = p.image || { data: "", mime: "" };
    const imageUrl = image.data ? "" : p.image_url;
    const r=await pool.query(`INSERT INTO products(category_id,price,image_url,image_data,image_mime,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active`,
      [p.category_id,p.price,imageUrl,image.data,image.mime,p.name_az,p.name_tr,p.name_ru,p.name_en,p.desc_az,p.desc_tr,p.desc_ru,p.desc_en,p.is_active]);
    res.status(201).json(presentProduct(r.rows[0]));
  }catch(e){res.status(400).json({error:e.message||"Məhsul əlavə olunmadı."});}
});
app.put("/api/admin/products/:id",auth,async(req,res)=>{
  try{
    const p=productInput(req.body);
    const imageSql = p.image ? ",image_url=$13,image_data=$14,image_mime=$15" : "";
    const params = [p.category_id,p.price,p.name_az,p.name_tr,p.name_ru,p.name_en,p.desc_az,p.desc_tr,p.desc_ru,p.desc_en,p.is_active,Number(req.params.id)];
    if (p.image) params.push(p.image.data ? "" : p.image_url, p.image.data, p.image.mime);
    const r=await pool.query(`UPDATE products SET category_id=$1,price=$2,name_az=$3,name_tr=$4,name_ru=$5,name_en=$6,desc_az=$7,desc_tr=$8,desc_ru=$9,desc_en=$10,is_active=$11,updated_at=NOW()${imageSql} WHERE id=$12 RETURNING id,category_id,price,image_url,(COALESCE(image_data,'')<>'') AS has_image,name_az,name_tr,name_ru,name_en,desc_az,desc_tr,desc_ru,desc_en,is_active`, params);
    if(!r.rowCount)return res.status(404).json({error:"Məhsul tapılmadı."});res.json(presentProduct(r.rows[0]));
  }catch(e){res.status(400).json({error:e.message||"Məhsul yenilənmədi."});}
});
app.delete("/api/admin/products/:id",auth,async(req,res)=>{
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
