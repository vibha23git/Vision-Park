require('dotenv').config();
const express=require('express'),http=require('http'),path=require('path'),crypto=require('crypto');
const mysql=require('mysql2/promise'),bcrypt=require('bcrypt'),jwt=require('jsonwebtoken');
const cookieParser=require('cookie-parser'),rateLimit=require('express-rate-limit');
const {Server}=require('socket.io');
const app=express(),server=http.createServer(app),io=new Server(server);
const prod=process.env.NODE_ENV==='production';
const pool=mysql.createPool({host:process.env.DB_HOST,port:process.env.DB_PORT,user:process.env.DB_USER,
 password:process.env.DB_PASSWORD,database:process.env.DB_NAME,timezone:'Z',connectionLimit:10});
app.use(express.json({limit:'10kb'}));app.use(cookieParser());
app.use(express.static(path.join(__dirname,'..')));
const wrap=f=>(q,s,n)=>f(q,s,n).catch(n);
const bad=(s,m,c=400)=>s.status(c).json({ok:false,error:m});
const ok=(s,d={})=>s.json({ok:true,...d});

// ---- auth middleware
const auth=wrap(async(q,s,n)=>{
 try{const p=jwt.verify(q.cookies.pv_token,process.env.JWT_SECRET);
  const [[u]]=await pool.execute('SELECT id,name,email,role,status FROM users WHERE id=?',[p.id]);
  if(!u||u.status!=='active')return bad(s,'Account unavailable',401);q.user=u;n();}
 catch{return bad(s,'Please log in',401);}});
const admin=(q,s,n)=>q.user.role==='admin'?n():bad(s,'Admin only',403);
const setCookie=(s,id)=>s.cookie('pv_token',jwt.sign({id},process.env.JWT_SECRET,{expiresIn:'8h'}),
 {httpOnly:true,sameSite:'strict',secure:prod,maxAge:8*3600e3});

// ---- slot status policy: operational > occupancy > reservation > available
const SLOT_SQL=`SELECT s.id,s.slot_code,s.zone,s.floor,s.slot_type,s.operational_status,s.current_occupancy,s.updated_at,
 EXISTS(SELECT 1 FROM reservations r WHERE r.parking_slot_id=s.id AND r.reservation_status='confirmed'
  AND r.start_time<=UTC_TIMESTAMP() AND r.end_time>UTC_TIMESTAMP()) AS reserved_now,
 CASE WHEN s.operational_status<>'active' THEN 'unavailable'
  WHEN s.current_occupancy='occupied' THEN 'occupied'
  WHEN EXISTS(SELECT 1 FROM reservations r WHERE r.parking_slot_id=s.id AND r.reservation_status='confirmed'
   AND r.start_time<=UTC_TIMESTAMP() AND r.end_time>UTC_TIMESTAMP()) THEN 'reserved'
  ELSE 'available' END AS status FROM parking_slots s`;
const changed=()=>io.emit('slots:changed');

// ---- auth routes
const lim=rateLimit({windowMs:15*60e3,max:30});
app.post('/api/auth/register',lim,wrap(async(q,s)=>{
 const {name,email,password,phone}=q.body||{};
 if(!name||name.length>100||!/^\S+@\S+\.\S+$/.test(email||'')||(password||'').length<8)return bad(s,'Name, valid email and 8+ character password required');
 const [[d]]=await pool.execute('SELECT id FROM users WHERE email=?',[email]);
 if(d)return bad(s,'Email already registered',409);
 const h=await bcrypt.hash(password,12);
 const [r]=await pool.execute('INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)',[name,email,phone||null,h]);
 setCookie(s,r.insertId);ok(s,{role:'user'});}));
app.post('/api/auth/login',lim,wrap(async(q,s)=>{
 const {email,password}=q.body||{};
 const [[u]]=await pool.execute('SELECT * FROM users WHERE email=?',[email||'']);
 if(!u||!(await bcrypt.compare(password||'',u.password_hash)))return bad(s,'Invalid email or password',401);
 if(u.status!=='active')return bad(s,'Account suspended',403);
 setCookie(s,u.id);ok(s,{role:u.role});}));
app.post('/api/auth/logout',(q,s)=>{s.clearCookie('pv_token');ok(s);});
app.get('/api/auth/me',auth,(q,s)=>ok(s,{user:q.user}));

// ---- parking
app.get('/api/parking/summary',auth,wrap(async(q,s)=>{
 const [rows]=await pool.query(SLOT_SQL);
 const c=t=>rows.filter(r=>r.status===t).length;
 const [[m]]=await pool.execute("SELECT COUNT(*) n FROM reservations WHERE user_id=? AND reservation_status='confirmed' AND end_time>UTC_TIMESTAMP()",[q.user.id]);
 const [[a]]=await pool.query("SELECT COUNT(*) n FROM reservations WHERE reservation_status='confirmed' AND end_time>UTC_TIMESTAMP()");
 const ev=rows.filter(r=>r.slot_type==='ev');
 ok(s,{total:rows.length,available:c('available'),occupied:c('occupied'),reserved:c('reserved'),unavailable:c('unavailable'),
  activeReservations:a.n,evAvailable:ev.filter(r=>r.status==='available').length,evTotal:ev.length,mine:m.n});}));
app.get('/api/parking',auth,wrap(async(q,s)=>{
 const [rows]=await pool.query(SLOT_SQL+' ORDER BY s.zone,s.slot_code');ok(s,{slots:rows});}));

// ---- vehicles
app.get('/api/vehicles',auth,wrap(async(q,s)=>{
 const [r]=await pool.execute('SELECT * FROM vehicles WHERE user_id=?',[q.user.id]);ok(s,{vehicles:r});}));
app.post('/api/vehicles',auth,wrap(async(q,s)=>{
 const b=q.body||{};const reg=(b.registration_number||'').toUpperCase().trim();
 if(!/^[A-Z0-9 -]{4,20}$/.test(reg))return bad(s,'Invalid registration number');
 try{await pool.execute('INSERT INTO vehicles(user_id,registration_number,vehicle_type,make,model,colour,is_ev) VALUES(?,?,?,?,?,?,?)',
  [q.user.id,reg,['car','suv','bike'].includes(b.vehicle_type)?b.vehicle_type:'car',b.make||null,b.model||null,b.colour||null,!!b.is_ev]);
 }catch(e){if(e.code==='ER_DUP_ENTRY')return bad(s,'Registration already exists',409);throw e;}
 ok(s);}));
app.delete('/api/vehicles/:id',auth,wrap(async(q,s)=>{
 const [[a]]=await pool.execute("SELECT COUNT(*) n FROM reservations WHERE vehicle_id=? AND reservation_status='confirmed' AND end_time>UTC_TIMESTAMP()",[q.params.id]);
 if(a.n)return bad(s,'Vehicle has active bookings',409);
 await pool.execute('DELETE FROM vehicles WHERE id=? AND user_id=?',[q.params.id,q.user.id]);ok(s);}));

// ---- reservations (transaction + row lock prevents double booking)
app.post('/api/reservations',auth,wrap(async(q,s)=>{
 const {slot_id,vehicle_id}=q.body||{};const st=new Date(q.body.start_time),en=new Date(q.body.end_time);
 if(isNaN(st)||isNaN(en)||en<=st||en-st>24*3600e3||st<Date.now()-60e3)return bad(s,'Invalid time range (max 24h, not in the past)');
 const c=await pool.getConnection();
 try{await c.beginTransaction();
  const [[slot]]=await c.execute('SELECT * FROM parking_slots WHERE id=? FOR UPDATE',[slot_id]);
  if(!slot||slot.operational_status!=='active'){await c.rollback();return bad(s,'Slot unavailable',409);}
  const [[v]]=await c.execute('SELECT * FROM vehicles WHERE id=? AND user_id=?',[vehicle_id,q.user.id]);
  if(!v){await c.rollback();return bad(s,'Vehicle not found',404);}
  if(slot.slot_type==='ev'&&!v.is_ev){await c.rollback();return bad(s,'EV slots need an EV-eligible vehicle',409);}
  if(slot.current_occupancy==='occupied'&&st<=new Date()){await c.rollback();return bad(s,'Slot is currently occupied',409);}
  const [o]=await c.execute("SELECT id FROM reservations WHERE parking_slot_id=? AND reservation_status='confirmed' AND start_time<? AND end_time>?",[slot.id,en,st]);
  if(o.length){await c.rollback();return bad(s,'Slot already booked for that time',409);}
  const ref='PV-'+crypto.randomBytes(4).toString('hex').toUpperCase();
  await c.execute('INSERT INTO reservations(booking_reference,user_id,vehicle_id,parking_slot_id,start_time,end_time) VALUES(?,?,?,?,?,?)',[ref,q.user.id,v.id,slot.id,st,en]);
  await c.commit();changed();ok(s,{booking_reference:ref});
 }catch(e){await c.rollback();throw e;}finally{c.release();}}));
app.get('/api/reservations/my',auth,wrap(async(q,s)=>{
 const [r]=await pool.execute(`SELECT r.id,r.booking_reference,r.start_time,r.end_time,r.reservation_status,p.slot_code,v.registration_number
  FROM reservations r JOIN parking_slots p ON p.id=r.parking_slot_id JOIN vehicles v ON v.id=r.vehicle_id
  WHERE r.user_id=? ORDER BY r.start_time DESC LIMIT 100`,[q.user.id]);ok(s,{reservations:r});}));
app.patch('/api/reservations/:id/cancel',auth,wrap(async(q,s)=>{
 const [r]=await pool.execute("UPDATE reservations SET reservation_status='cancelled' WHERE id=? AND user_id=? AND reservation_status='confirmed'",[q.params.id,q.user.id]);
 if(!r.affectedRows)return bad(s,'Reservation cannot be cancelled',404);changed();ok(s);}));

// ---- admin
app.get('/api/admin/summary',auth,admin,wrap(async(q,s)=>{
 const [[u]]=await pool.query('SELECT COUNT(*) n FROM users');const [[r]]=await pool.query('SELECT COUNT(*) n FROM reservations');
 const [[h]]=await pool.query('SELECT MAX(observed_at) last_reading FROM occupancy_events');ok(s,{users:u.n,reservations:r.n,lastReading:h.last_reading});}));
app.patch('/api/admin/parking-slots/:id',auth,admin,wrap(async(q,s)=>{
 const {operational_status,slot_type}=q.body||{};
 if(operational_status&&!['active','maintenance','blocked'].includes(operational_status))return bad(s,'Bad status');
 if(slot_type&&!['regular','ev','accessible','reserved'].includes(slot_type))return bad(s,'Bad type');
 await pool.execute('UPDATE parking_slots SET operational_status=COALESCE(?,operational_status),slot_type=COALESCE(?,slot_type) WHERE id=?',[operational_status||null,slot_type||null,q.params.id]);
 await pool.execute('INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES(?,?,?,?)',[q.user.id,'update_slot','slot',q.params.id]);
 changed();ok(s);}));

// ---- IoT / vision ingest (device key; backend reconciles)
// Policy: latest reading wins, but if the other source disagreed within 30s the slot becomes 'unknown' (needs verification).
app.post('/api/iot/observation',wrap(async(q,s)=>{
 if(q.get('x-device-key')!==process.env.DEVICE_API_KEY)return bad(s,'Unauthorized',401);
 const {slot_code,source,status,confidence}=q.body||{};
 if(!['camera','sensor'].includes(source)||!['free','occupied'].includes(status))return bad(s,'Bad payload');
 const [[slot]]=await pool.execute('SELECT id FROM parking_slots WHERE slot_code=?',[slot_code]);
 if(!slot)return bad(s,'Unknown slot',404);
 await pool.execute('INSERT INTO occupancy_events(parking_slot_id,source,observed_status,confidence) VALUES(?,?,?,?)',[slot.id,source,status,confidence??null]);
 const [[o]]=await pool.execute("SELECT observed_status FROM occupancy_events WHERE parking_slot_id=? AND source<>? AND observed_at>UTC_TIMESTAMP()-INTERVAL 30 SECOND ORDER BY observed_at DESC LIMIT 1",[slot.id,source]);
 const final=o&&o.observed_status!==status?'unknown':status;
 await pool.execute('UPDATE parking_slots SET current_occupancy=? WHERE id=?',[final,slot.id]);changed();ok(s,{final});}));

// ---- reservation expiry / no-show job (backend, not frontend)
setInterval(()=>pool.query("UPDATE reservations SET reservation_status='completed' WHERE reservation_status='confirmed' AND end_time<UTC_TIMESTAMP()").then(changed).catch(()=>{}),60e3);

app.use((e,q,s,n)=>{console.error(e.message);bad(s,'Server error',500);});
server.listen(process.env.PORT||3000,()=>console.log('ParkVision on port '+(process.env.PORT||3000)));
