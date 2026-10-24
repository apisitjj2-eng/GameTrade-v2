const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database(path.join(__dirname, "gametrade.db"));
const PORT = Number(process.env.PORT) || 3000;

// Render runs behind a reverse proxy. Trust it so secure cookies work with HTTPS.
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 name TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'buyer'
 CHECK(role IN ('buyer','seller','admin'))
);
CREATE TABLE IF NOT EXISTS listings (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 seller_id INTEGER NOT NULL REFERENCES users(id),
 game TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 price INTEGER NOT NULL CHECK(price > 0),
 status TEXT NOT NULL DEFAULT 'active'
 CHECK(status IN ('active','reserved','sold','removed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 listing_id INTEGER NOT NULL REFERENCES listings(id),
 buyer_id INTEGER NOT NULL REFERENCES users(id),
 seller_id INTEGER NOT NULL REFERENCES users(id),
 price INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','delivered','completed','disputed','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS disputes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL UNIQUE REFERENCES orders(id),
 opened_by INTEGER NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open'
 CHECK(status IN ('open','resolved')),
 resolution TEXT
);
`);

app.use(express.json({limit:"20kb"}));
app.use(session({
 secret: process.env.SESSION_SECRET || "local-demo-change-before-online-9f2c71b6",
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly:true, sameSite:"lax", secure: process.env.NODE_ENV === "production", maxAge: 2*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
function auth(req,res,next) {
 if (!req.session.user) return res.status(401).json({error:"กรุณาเข้าสู่ระบบก่อน"});
 req.user = req.session.user; next();
}
function role(...roles) {
 return (req,res,next) => roles.includes(req.user.role)
  ? next() : res.status(403).json({error:"บัญชีนี้ไม่มีสิทธิ์ทำรายการ"});
}
function str(v,max) { return typeof v==="string" && v.trim().length>0 && v.trim().length<=max; }
function publicUser(u) { return {id:u.id,email:u.email,name:u.name,role:u.role}; }

app.get("/api/me", (req,res) => res.json({user:req.session.user || null}));

app.post("/api/register", wrap(async (req,res) => {
 const email = typeof req.body.email==="string" ? req.body.email.trim().toLowerCase() : "";
 const {password,name} = req.body;
 if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length>254)
  return res.status(400).json({error:"กรุณากรอกอีเมลให้ถูกต้อง"});
 if (typeof password!=="string" || password.length<10 || password.length>72)
  return res.status(400).json({error:"รหัสผ่านต้องมี 10–72 ตัวอักษร"});
 if (!str(name,60)) return res.status(400).json({error:"กรุณากรอกชื่อ 1–60 ตัวอักษร"});
 try {
  const hash = await bcrypt.hash(password, 10);
  const result = db.prepare("INSERT INTO users(email,password_hash,name) VALUES(?,?,?)")
   .run(email,hash,name.trim());
  const user = {id:Number(result.lastInsertRowid),email,name:name.trim(),role:"buyer"};
  req.session.user=user;
  res.status(201).json({user});
 } catch(e) {
  if (String(e.code).includes("CONSTRAINT")) return res.status(409).json({error:"อีเมลนี้ถูกใช้แล้ว"});
  throw e;
 }
}));

app.post("/api/login", wrap(async (req,res) => {
 const email = typeof req.body.email==="string" ? req.body.email.trim().toLowerCase() : "";
 const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if (!user || typeof req.body.password!=="string" || !await bcrypt.compare(req.body.password,user.password_hash))
  return res.status(401).json({error:"อีเมลหรือรหัสผ่านไม่ถูกต้อง"});
 req.session.user=publicUser(user);
 res.json({user:req.session.user});
}));
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.post("/api/role",auth,(req,res)=>{
 if (!["buyer","seller"].includes(req.body.role)) return res.status(400).json({error:"บทบาทไม่ถูกต้อง"});
 if (req.user.role==="admin") return res.status(403).json({error:"บัญชีแอดมินเปลี่ยนบทบาทไม่ได้"});
 db.prepare("UPDATE users SET role=? WHERE id=?").run(req.body.role,req.user.id);
 req.session.user.role=req.body.role;
 res.json({user:req.session.user});
});

app.get("/api/listings",(req,res)=>{
 const q = typeof req.query.q==="string" ? `%${req.query.q.slice(0,80)}%` : "%";
 const rows=db.prepare(`SELECT l.*,u.name AS seller_name FROM listings l JOIN users u ON u.id=l.seller_id
 WHERE l.status='active' AND (l.title LIKE ? OR l.game LIKE ? OR l.description LIKE ?)
 ORDER BY l.id DESC LIMIT 100`).all(q,q,q);
 res.json({listings:rows});
});
app.get("/api/my-listings",auth,role("seller","admin"),(req,res)=>{
 const rows=db.prepare(`SELECT l.*,u.name AS seller_name FROM listings l JOIN users u ON u.id=l.seller_id WHERE l.seller_id=? ORDER BY l.id DESC`).all(req.user.id);
 res.json({listings:rows});
});

app.post("/api/listings",auth,role("seller"),(req,res)=>{
 const {game,title,description,price}=req.body;
 const n=Number(price);
 if(!str(game,60)||!str(title,120)||!str(description,2000)||!Number.isSafeInteger(n)||n<1||n>100000000)
  return res.status(400).json({error:"ตรวจสอบข้อมูลประกาศและราคา (ราคาเป็นบาทจำนวนเต็ม)"});
 const result=db.prepare("INSERT INTO listings(seller_id,game,title,description,price) VALUES(?,?,?,?,?)")
  .run(req.user.id,game.trim(),title.trim(),description.trim(),n);
 res.status(201).json({id:Number(result.lastInsertRowid)});
});
app.delete("/api/listings/:id",auth,role("seller"),(req,res)=>{
 const r=db.prepare("UPDATE listings SET status='removed' WHERE id=? AND seller_id=? AND status='active'")
  .run(req.params.id,req.user.id);
 if(!r.changes)return res.status(404).json({error:"ไม่พบประกาศของคุณ"});
 res.json({ok:true});
});

app.post("/api/orders",auth,role("buyer"),(req,res)=>{
 const buy=db.transaction(()=>{
  const l=db.prepare("SELECT * FROM listings WHERE id=?").get(req.body.listingId);
  if(!l||l.status!=="active")throw new Error("รายการนี้ไม่พร้อมขายแล้ว");
  if(l.seller_id===req.user.id)throw new Error("ซื้อประกาศของตัวเองไม่ได้");
  const result=db.prepare("INSERT INTO orders(listing_id,buyer_id,seller_id,price) VALUES(?,?,?,?)")
   .run(l.id,req.user.id,l.seller_id,l.price);
  db.prepare("UPDATE listings SET status='reserved' WHERE id=?").run(l.id);
  return Number(result.lastInsertRowid);
 });
 try { const id=buy();res.status(201).json({id,message:"สร้างคำสั่งซื้อทดลองแล้ว ยังไม่มีการชำระเงินจริง"}); }
 catch(e){res.status(409).json({error:e.message});}
});
app.get("/api/orders",auth,(req,res)=>{
 const rows=db.prepare(`SELECT o.*,l.title,l.game,b.name buyer_name,s.name seller_name
 FROM orders o JOIN listings l ON l.id=o.listing_id
 JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id
 WHERE o.buyer_id=? OR o.seller_id=? OR ?='admin' ORDER BY o.id DESC`).all(req.user.id,req.user.id,req.user.role);
 res.json({orders:rows});
});
app.post("/api/orders/:id/deliver",auth,role("seller"),(req,res)=>{
 const r=db.prepare("UPDATE orders SET status='delivered' WHERE id=? AND seller_id=? AND status='pending'")
  .run(req.params.id,req.user.id);
 if(!r.changes)return res.status(409).json({error:"คำสั่งซื้อไม่อยู่ในสถานะที่ส่งมอบได้"});
 res.json({ok:true});
});
app.post("/api/orders/:id/complete",auth,role("buyer"),(req,res)=>{
 const o=db.prepare("SELECT * FROM orders WHERE id=? AND buyer_id=?").get(req.params.id,req.user.id);
 if(!o||o.status!=="delivered")return res.status(409).json({error:"คำสั่งซื้อนี้ยังยืนยันไม่ได้"});
 const tx=db.transaction(()=>{
  db.prepare("UPDATE orders SET status='completed' WHERE id=?").run(o.id);
  db.prepare("UPDATE listings SET status='sold' WHERE id=?").run(o.listing_id);
 });
 tx();res.json({ok:true,message:"บันทึกการรับมอบแล้ว ไม่มีการจ่ายเงินจริง"});
});
app.post("/api/orders/:id/dispute",auth,(req,res)=>{
 const o=db.prepare("SELECT * FROM orders WHERE id=?").get(req.params.id);
 if(!o||![o.buyer_id,o.seller_id].includes(req.user.id)||!["pending","delivered"].includes(o.status))
  return res.status(409).json({error:"ไม่สามารถเปิดข้อพิพาทได้"});
 if(!str(req.body.reason,1000))return res.status(400).json({error:"กรุณาระบุเหตุผล"});
 try {
  const tx=db.transaction(()=>{
   db.prepare("INSERT INTO disputes(order_id,opened_by,reason) VALUES(?,?,?)").run(o.id,req.user.id,req.body.reason.trim());
   db.prepare("UPDATE orders SET status='disputed' WHERE id=?").run(o.id);
  });
  tx();res.status(201).json({ok:true});
 } catch(e){res.status(409).json({error:"ข้อพิพาทนี้อาจมีอยู่แล้ว"});}
});
app.get("/api/admin/disputes",auth,role("admin"),(req,res)=>{
 res.json({disputes:db.prepare("SELECT d.*,o.status order_status FROM disputes d JOIN orders o ON o.id=d.order_id ORDER BY d.id DESC").all()});
});
app.post("/api/admin/disputes/:id/resolve",auth,role("admin"),(req,res)=>{
 const {resolution,outcome}=req.body;
 if(!str(resolution,1000)||!["completed","cancelled"].includes(outcome))
  return res.status(400).json({error:"ข้อมูลไม่ถูกต้อง"});
 const d=db.prepare("SELECT d.*,o.listing_id,o.status order_status FROM disputes d JOIN orders o ON o.id=d.order_id WHERE d.id=?").get(req.params.id);
 if(!d||d.status!=="open"||d.order_status!=="disputed")return res.status(409).json({error:"ข้อพิพาทนี้ดำเนินการไม่ได้"});
 const tx=db.transaction(()=>{
  db.prepare("UPDATE disputes SET status='resolved',resolution=? WHERE id=?").run(resolution.trim(),d.id);
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(outcome,d.order_id);
  if(outcome==="completed")db.prepare("UPDATE listings SET status='sold' WHERE id=?").run(d.listing_id);
  else db.prepare("UPDATE listings SET status='active' WHERE id=? AND status='reserved'").run(d.listing_id);
 });
 tx();res.json({ok:true,message:"บันทึกผลแล้ว ไม่มีการจ่ายหรือคืนเงินจริง"});
});

app.get("/api/admin/users",auth,role("admin"),(req,res)=>{
 res.json({users:db.prepare("SELECT id,email,name,role FROM users ORDER BY id DESC LIMIT 200").all()});
});
app.use("/api",(req,res)=>res.status(404).json({error:"ไม่พบ API"}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"เกิดข้อผิดพลาดในระบบ"});});
app.listen(PORT,"0.0.0.0",()=>console.log(`GameTrade เปิดแล้วที่พอร์ต ${PORT}`));
