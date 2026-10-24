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
 CHECK(role IN ('buyer','seller','admin')),
 balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0)
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
 commission_rate INTEGER NOT NULL DEFAULT 7,
 commission_amount INTEGER NOT NULL DEFAULT 0,
 seller_net INTEGER NOT NULL DEFAULT 0,
 payment_mode TEXT NOT NULL DEFAULT 'demo',
 status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','delivered','completed','disputed','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS premium_subscriptions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
 plan TEXT NOT NULL CHECK(plan IN ('monthly','yearly')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled','expired')),
 price INTEGER NOT NULL,
 started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wallet_transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 admin_id INTEGER NOT NULL REFERENCES users(id),
 amount INTEGER NOT NULL,
 balance_after INTEGER NOT NULL,
 note TEXT NOT NULL,
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

// Backward-compatible schema updates for existing demo databases.
try { db.exec("ALTER TABLE users ADD COLUMN balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0)"); } catch (e) { if (!String(e.message).includes("duplicate column name")) throw e; }
for (const [column, definition] of [
  ["commission_rate", "INTEGER NOT NULL DEFAULT 7"],
  ["commission_amount", "INTEGER NOT NULL DEFAULT 0"],
  ["seller_net", "INTEGER NOT NULL DEFAULT 0"],
  ["payment_mode", "TEXT NOT NULL DEFAULT 'demo'"]
]) {
  try { db.exec(`ALTER TABLE orders ADD COLUMN ${column} ${definition}`); } catch (e) {
    if (!String(e.message).includes("duplicate column name")) throw e;
  }
}
db.exec("UPDATE orders SET commission_amount = CAST(ROUND(price * 0.07) AS INTEGER), seller_net = price - CAST(ROUND(price * 0.07) AS INTEGER) WHERE commission_amount = 0 AND seller_net = 0");

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
app.post("/api/admin/unlock", auth, wrap(async (req,res) => {
 const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
 const adminPin = process.env.ADMIN_PIN;

 if (!adminEmail || !adminPin)
  return res.status(503).json({error:"เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า Admin"});
 if (String(req.user.email).toLowerCase() !== adminEmail)
  return res.status(403).json({error:"บัญชีนี้ไม่ได้รับอนุญาตให้เป็นแอดมิน"});
 if (typeof req.body.pin !== "string" || req.body.pin !== adminPin)
  return res.status(401).json({error:"PIN ไม่ถูกต้อง"});

 req.session.user = {...req.session.user, role:"admin"};
 req.session.save(err => {
  if (err) return res.status(500).json({error:"บันทึก Session ไม่สำเร็จ"});
  res.json({user:req.session.user});
 });
}));

app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

// Premium is simulation-only: this endpoint never charges money.
function premiumFor(userId) {
 const sub = db.prepare("SELECT * FROM premium_subscriptions WHERE user_id=?").get(userId);
 if (!sub) return {active:false, subscription:null};
 if (sub.status === "active" && Date.parse(sub.expires_at.replace(" ","T")+"Z") <= Date.now()) {
  db.prepare("UPDATE premium_subscriptions SET status='expired' WHERE user_id=?").run(userId);
  sub.status = "expired";
 }
 return {active:sub.status === "active", subscription:sub};
}
app.get("/api/premium",auth,(req,res)=>res.json({mode:"DEMO_ONLY",...premiumFor(req.user.id)}));
app.post("/api/premium/subscribe",auth,(req,res)=>{
 const plan=req.body.plan;
 const plans={monthly:{price:99,days:30},yearly:{price:999,days:365}};
 if(!plans[plan]) return res.status(400).json({error:"กรุณาเลือกแพ็กเกจที่ถูกต้อง"});
 const current=premiumFor(req.user.id);
 if(current.active) return res.status(409).json({error:"บัญชีนี้มี Premium ทดลองที่ยังใช้งานอยู่แล้ว"});
 const {price,days}=plans[plan];
 const now=new Date(),expires=new Date(now.getTime()+days*86400000);
 const sqlDate=d=>d.toISOString().slice(0,19).replace("T"," ");
 db.prepare(`INSERT INTO premium_subscriptions(user_id,plan,status,price,started_at,expires_at)
 VALUES(?,?,'active',?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan,status='active',price=excluded.price,started_at=excluded.started_at,expires_at=excluded.expires_at`)
 .run(req.user.id,plan,price,sqlDate(now),sqlDate(expires));
 res.status(201).json({mode:"DEMO_ONLY",...premiumFor(req.user.id),message:"เปิด Premium ทดลองแล้ว ไม่มีการเรียกเก็บเงินจริง"});
});
app.post("/api/premium/cancel",auth,(req,res)=>{
 const sub=premiumFor(req.user.id);
 if(!sub.active) return res.status(409).json({error:"ไม่มี Premium ที่กำลังใช้งาน"});
 db.prepare("UPDATE premium_subscriptions SET status='cancelled' WHERE user_id=?").run(req.user.id);
 res.json({mode:"DEMO_ONLY",...premiumFor(req.user.id),message:"ยกเลิก Premium ทดลองแล้ว"});
});

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
  const commission = Math.round(l.price * 0.07);
  const sellerNet = l.price - commission;
  const result=db.prepare("INSERT INTO orders(listing_id,buyer_id,seller_id,price,commission_rate,commission_amount,seller_net,payment_mode) VALUES(?,?,?,?,7,?,?,'demo')")
   .run(l.id,req.user.id,l.seller_id,l.price,commission,sellerNet);
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
app.get("/api/admin/commission-summary",auth,role("admin"),(req,res)=>{
 const summary=db.prepare(`SELECT COUNT(*) AS order_count,
 COALESCE(SUM(CASE WHEN status='completed' THEN price ELSE 0 END),0) AS completed_gross,
 COALESCE(SUM(CASE WHEN status='completed' THEN commission_amount ELSE 0 END),0) AS completed_commission,
 COALESCE(SUM(CASE WHEN status IN ('pending','delivered','disputed') THEN commission_amount ELSE 0 END),0) AS pending_commission,
 COALESCE(SUM(CASE WHEN status='completed' THEN seller_net ELSE 0 END),0) AS completed_seller_net
 FROM orders WHERE payment_mode='demo'`).get();
 res.json({mode:"DEMO_ONLY",summary});
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
 res.json({users:db.prepare("SELECT id,email,name,role,balance FROM users ORDER BY id DESC LIMIT 200").all()});
});
// All wallet changes are simulated and only an authenticated admin can perform them.
app.post("/api/admin/users/:id/balance",auth,role("admin"),(req,res)=>{
 const userId=Number(req.params.id), amount=Number(req.body.amount), action=req.body.action;
 const note=str(req.body.note||"ปรับยอดโดยแอดมิน",200)?(req.body.note||"ปรับยอดโดยแอดมิน").trim():"ปรับยอดโดยแอดมิน";
 if(!Number.isSafeInteger(userId)||userId<1||!Number.isSafeInteger(amount)||amount<0||amount>1000000000||!['add','subtract','set'].includes(action)) return res.status(400).json({error:"กรุณาตรวจสอบบัญชี จำนวนเงิน และรูปแบบการปรับยอด"});
 const target=db.prepare("SELECT id,role,balance FROM users WHERE id=?").get(userId);
 if(!target)return res.status(404).json({error:"ไม่พบบัญชีผู้ใช้"});
 if(target.role==='admin' && target.id===req.user.id)return res.status(400).json({error:"ไม่สามารถปรับยอดบัญชีแอดมินที่กำลังใช้งานได้"});
 let next=action==='add'?target.balance+amount:action==='subtract'?target.balance-amount:amount;
 if(!Number.isSafeInteger(next)||next<0||next>1000000000)return res.status(400).json({error:"ยอดเงินต้องอยู่ระหว่าง 0 ถึง 1,000,000,000 บาทจำลอง"});
 const delta=next-target.balance;
 const tx=db.transaction(()=>{db.prepare("UPDATE users SET balance=? WHERE id=?").run(next,userId);db.prepare("INSERT INTO wallet_transactions(user_id,admin_id,amount,balance_after,note) VALUES(?,?,?,?,?)").run(userId,req.user.id,delta,next,note);});
 tx();res.json({ok:true,balance:next,message:`ปรับยอดจำลองแล้ว ยอดคงเหลือ ${next} บาท`});
});
app.get("/api/admin/wallet-transactions",auth,role("admin"),(req,res)=>{
 res.json({transactions:db.prepare(`SELECT t.*,u.name AS user_name,u.email AS user_email,a.name AS admin_name FROM wallet_transactions t JOIN users u ON u.id=t.user_id JOIN users a ON a.id=t.admin_id ORDER BY t.id DESC LIMIT 100`).all()});
});
app.post("/api/admin/users/:id/role",auth,role("admin"),(req,res)=>{
 const id=Number(req.params.id), roleName=req.body.role;
 if(!Number.isSafeInteger(id)||!['buyer','seller'].includes(roleName))return res.status(400).json({error:"ข้อมูลบทบาทไม่ถูกต้อง"});
 const target=db.prepare("SELECT id,role FROM users WHERE id=?").get(id);
 if(!target)return res.status(404).json({error:"ไม่พบบัญชีผู้ใช้"});
 if(target.role==='admin')return res.status(400).json({error:"ไม่สามารถเปลี่ยนบทบาทแอดมินผ่านเมนูนี้ได้"});
 db.prepare("UPDATE users SET role=? WHERE id=?").run(roleName,id);res.json({ok:true});
});
app.post("/api/admin/listings/:id/remove",auth,role("admin"),(req,res)=>{
 const id=Number(req.params.id);if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"รหัสประกาศไม่ถูกต้อง"});
 const r=db.prepare("UPDATE listings SET status='removed' WHERE id=? AND status!='removed'").run(id);
 if(!r.changes)return res.status(404).json({error:"ไม่พบประกาศหรือถูกลบไปแล้ว"});res.json({ok:true});
});
app.post("/api/admin/users/:id/premium",auth,role("admin"),(req,res)=>{
 const id=Number(req.params.id), action=req.body.action;
 if(!Number.isSafeInteger(id)||id<1||!['grant','revoke'].includes(action))return res.status(400).json({error:"ข้อมูล Premium ไม่ถูกต้อง"});
 const target=db.prepare("SELECT id FROM users WHERE id=?").get(id);if(!target)return res.status(404).json({error:"ไม่พบบัญชีผู้ใช้"});
 if(action==='revoke'){db.prepare("UPDATE premium_subscriptions SET status='cancelled' WHERE user_id=? AND status='active'").run(id);return res.json({ok:true,message:"ปิด Premium ทดลองแล้ว"});}
 const now=new Date(),end=new Date(now.getTime()+30*86400000),fmt=d=>d.toISOString().slice(0,19).replace('T',' ');
 db.prepare(`INSERT INTO premium_subscriptions(user_id,plan,status,price,started_at,expires_at) VALUES(?,'monthly','active',0,?,?) ON CONFLICT(user_id) DO UPDATE SET plan='monthly',status='active',price=0,started_at=excluded.started_at,expires_at=excluded.expires_at`).run(id,fmt(now),fmt(end));res.json({ok:true,message:"เปิด Premium ทดลอง 30 วันแล้ว"});
});
app.use("/api",(req,res)=>res.status(404).json({error:"ไม่พบ API"}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"เกิดข้อผิดพลาดในระบบ"});});
app.listen(PORT,"0.0.0.0",()=>console.log(`GameTrade เปิดแล้วที่พอร์ต ${PORT}`));
