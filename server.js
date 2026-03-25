const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Security middleware
const rateLimit = (windowMs, max) => {
  const requests = new Map();
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const windowStart = now - windowMs;
    if (!requests.has(key)) requests.set(key, []);
    const userReqs = requests.get(key).filter(t => t > windowStart);
    requests.set(key, userReqs);
    if (userReqs.length >= max) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    userReqs.push(now);
    next();
  };
};
const loginLimiter = rateLimit(15 * 60 * 1000, 10); // 10 login attempts per 15 min
const apiLimiter = rateLimit(60 * 1000, 100); // 100 req per min

// Input sanitizer
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<[^>]+>/g, '')
            .trim()
            .substring(0, 5000);
}

const app = express();
const PORT = process.env.PORT || 3000;
// ✅ FIX: JWT_SECRET अब सिर्फ environment variable से आएगा
// Deployment पर: export JWT_SECRET="कोई लंबी random string"
// Netlify/Render पर: Environment Variables में set करें
if (!process.env.JWT_SECRET) {
  console.error('⚠️  SECURITY ERROR: JWT_SECRET environment variable set नहीं है!');
  console.error('    Server start करने से पहले: export JWT_SECRET="your-long-random-secret"');
  process.exit(1); // Secret नहीं है तो server बंद
}
const JWT_SECRET = process.env.JWT_SECRET;

// Database file
const DB_FILE = 'database.json';

// Load or initialize database
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    return JSON.parse(fs.readFileSync(DB_FILE));
  }
  return initDB();
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function initDB() {
  const db = {
    users: [],
    admins: [],
    categories: [],
    products: [],
    orders: [],
    order_items: [],
    coupons: [],
    reviews: [],
    blogs: [],
    testimonials: [],
    inquiries: [],
    dealer_inquiries: [],
    affiliates: [],
    settings: {},
    seo_settings: {}
  };

  // Create default super admin
  const defaultPass = process.env.ADMIN_DEFAULT_PASSWORD || 'tharoil2026';
  if (!process.env.ADMIN_DEFAULT_PASSWORD) {
    console.warn('WARNING: ADMIN_DEFAULT_PASSWORD not set. Using default password tharoil2026 - CHANGE IMMEDIATELY!');
  }
  const hashedPassword = bcrypt.hashSync(defaultPass, 10);
  db.admins.push({
    id: uuidv4(),
    name: 'Super Admin',
    username: 'admin',
    password: hashedPassword,
    role: 'super_admin',
    permissions: {
      products: true, orders: true, customers: true, blogs: true, coupons: true,
      inquiries: true, testimonials: true, affiliates: true, settings: true, seo: true, admins: true
    },
    created_by: null,
    is_active: true,
    created_at: new Date().toISOString()
  });

  // Default settings
  db.settings = {
    site_name: 'Thar Oil',
    site_logo: '/img/logo.png',
    contact_email: 'info@tharoil.com',
    contact_mobile: '+91 9876543210',
    address: 'Thar Oil, Rajasthan, India',
    gst_number: 'GSTIN123456789',
    food_license: 'FL123456789',
    razorpay_key_id: '',
    razorpay_key_secret: '',
    shiprocket_email: '',
    shiprocket_password: '',
    facebook_url: '',
    instagram_url: '',
    twitter_url: '',
    youtube_url: ''
  };

  // SEO defaults
  db.seo_settings = {
    meta_title: 'Thar Oil - 100% Natural Cold-Pressed Oils',
    meta_description: 'Premium quality cold-pressed oils from Thar Oil. Pure, natural and authentic.',
    meta_keywords: '',
    google_analytics_id: '',
    facebook_pixel_id: '',
    google_search_console_verification: '',
    custom_scripts: ''
  };

  // Default categories
  const defaultCategories = [
    { name: 'Cold Pressed Oils', slug: 'cold-pressed-oils', description: 'Pure cold-pressed oils extracted at room temperature' },
    { name: 'Mustard Oil', slug: 'mustard-oil', description: 'Traditional mustard oil for cooking' },
    { name: 'Sesame Oil', slug: 'sesame-oil', description: 'Premium sesame oil' },
    { name: 'Groundnut Oil', slug: 'groundnut-oil', description: 'Pure groundnut oil' },
    { name: 'Coconut Oil', slug: 'coconut-oil', description: 'Virgin coconut oil' }
  ];

  defaultCategories.forEach(cat => {
    db.categories.push({ ...cat, id: uuidv4(), is_active: true, created_at: new Date().toISOString(), product_count: 0 });
  });

  saveDB(db);
  console.log('Default admin: admin / tharoil2026');
  return db;
}

let db = loadDB();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://tharoil20.netlify.app'],
  credentials: true
}));

// ✅ FIX: Strong security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://checkout.razorpay.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "img-src 'self' data: https:; connect-src 'self' https://api.razorpay.com; " +
    "frame-src https://api.razorpay.com; frame-ancestors 'none';"
  );
  next();
});
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(apiLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));
app.use('/img', express.static('img'));

// Ensure directories exist
['uploads', 'uploads/products', 'uploads/blogs'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer config for file uploads
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const imageFileFilter = (req, file, cb) => {
  if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only JPG, PNG, and WebP images are allowed'), false);
  }
};
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/products'),
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
    cb(null, uuidv4() + safeExt);
  }
});
const upload = multer({ storage, fileFilter: imageFileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// Logo upload storage
const logoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'img'),
  filename: (req, file, cb) => cb(null, 'logo' + path.extname(file.originalname))
});
const logoUpload = multer({ storage: logoStorage });

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Role check middleware
const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.admin.role)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

// ============ PUBLIC ROUTES ============

// Get all settings
app.get('/api/settings', (req, res) => {
  // FIX: Secret keys client ko nahi jaane chahiye
  const { razorpay_key_secret, shiprocket_password, ...publicSettings } = db.settings;
  res.json(publicSettings);
});

// Get SEO settings
app.get('/api/seo', (req, res) => {
  res.json(db.seo_settings);
});

// Get categories
app.get('/api/categories', (req, res) => {
  const active = db.categories.filter(c => c.is_active).sort((a,b) => a.name.localeCompare(b.name));
  res.json(active);
});

// Get products
app.get('/api/products', (req, res) => {
  const { category, featured, search } = req.query;
  let products = db.products.filter(p => p.is_active);

  if (category) {
    const cat = db.categories.find(c => c.slug === category);
    if (cat) products = products.filter(p => p.category_id === cat.id);
  }
  if (featured) products = products.filter(p => p.is_featured);
  if (search) {
    const s = search.toLowerCase();
    products = products.filter(p => p.name.toLowerCase().includes(s) || (p.description && p.description.toLowerCase().includes(s)));
  }

  products.forEach(p => {
    const cat = db.categories.find(c => c.id === p.category_id);
    p.category_name = cat ? cat.name : null;
  });

  res.json(products.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Get single product
app.get('/api/products/:slug', (req, res) => {
  const product = db.products.find(p => p.slug === req.params.slug && p.is_active);
  if (product) {
    const cat = db.categories.find(c => c.id === product.category_id);
    product.category_name = cat ? cat.name : null;
    product.reviews = db.reviews
      .filter(r => r.product_id === product.id && r.is_approved)
      .map(r => {
        const user = db.users.find(u => u.id === r.user_id);
        return { ...r, user_name: user ? user.name : 'Anonymous' };
      })
      .sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 10);
  }
  res.json(product || {});
});

// Get blogs
app.get('/api/blogs', (req, res) => {
  const blogs = db.blogs.filter(b => b.status === 'published').sort((a,b) => new Date(b.published_at) - new Date(a.published_at));
  res.json(blogs);
});

// Get single blog
app.get('/api/blogs/:slug', (req, res) => {
  const blog = db.blogs.find(b => b.slug === req.params.slug && b.status === 'published');
  res.json(blog || {});
});

// Get testimonials
app.get('/api/testimonials', (req, res) => {
  const testimonials = db.testimonials.filter(t => t.is_active).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  res.json(testimonials);
});

// Validate coupon
app.post('/api/coupons/validate', (req, res) => {
  const { code, order_total } = req.body;
  const coupon = db.coupons.find(c => c.code === code && c.is_active);
  if (!coupon) return res.json({ valid: false, error: 'Invalid coupon' });
  if (coupon.valid_from && new Date(coupon.valid_from) > new Date()) return res.json({ valid: false, error: 'Coupon not started' });
  if (coupon.valid_until && new Date(coupon.valid_until) < new Date()) return res.json({ valid: false, error: 'Coupon expired' });
  if (coupon.max_uses && coupon.used_count >= coupon.max_uses) return res.json({ valid: false, error: 'Coupon limit reached' });
  if (coupon.min_order && order_total < coupon.min_order) return res.json({ valid: false, error: `Minimum order ₹${coupon.min_order} required` });
  res.json({ valid: true, discount: coupon });
});

// User registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, mobile, whatsapp, address, city, state, pincode, dob, gender, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: 'Name and password required' });
    const existing = db.users.find(u => u.email === email || u.mobile === mobile);
    if (existing) return res.status(400).json({ error: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      name, email: email || null, mobile: mobile || null, whatsapp: whatsapp || null,
      address: address || null, city: city || null, state: state || null, pincode: pincode || null,
      dob: dob || null, gender: gender || null, password: hashedPassword,
      email_verified: 0, mobile_verified: 0, is_blocked: 0, created_at: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);
    const token = jwt.sign({ id: user.id, name: user.name, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, mobile: user.mobile } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// User login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, mobile, password } = req.body;
  const user = db.users.find(u => u.email === email || u.mobile === mobile);
  if (!user) return res.status(400).json({ error: 'User not found' });
  if (user.is_blocked) return res.status(400).json({ error: 'Account blocked' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid password' });
  const token = jwt.sign({ id: user.id, name: user.name, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, mobile: user.mobile } });
});

// Submit inquiry
app.post('/api/inquiries', (req, res) => {
  const { name, email, mobile, whatsapp, message, type } = req.body;
  const cleanName = sanitize(name || '');
  const cleanMessage = sanitize(message || '');
  if (!cleanName || !cleanMessage) return res.status(400).json({ error: 'Name and message required' });
  db.inquiries.push({
    id: uuidv4(), name: cleanName, email: sanitize(email||''), mobile: sanitize(mobile||''), 
    whatsapp: sanitize(whatsapp||''), message: cleanMessage, type: type || 'general',
    status: 'pending', reply: null, replied_by: null, created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Submit dealer inquiry
app.post('/api/dealer-inquiry', (req, res) => {
  const { name, age, mobile, whatsapp, email, shop_address, city, state, pincode, message } = req.body;
  db.dealer_inquiries.push({
    id: uuidv4(), name, age, mobile, whatsapp, email, shop_address, city, state, pincode, message,
    status: 'pending', created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Apply for affiliate
app.post('/api/affiliate/apply', (req, res) => {
  const { name, social_platform, social_url } = req.body;
  db.affiliates.push({
    id: uuidv4(), user_id: null, name, social_platform, social_url,
    status: 'pending', created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// ✅ FIX: Order creation - Server-side price verification
// Client se sirf product IDs aur quantities aate hain, prices server calculate karta hai
app.post('/api/orders', (req, res) => {
  const { user_id, guest_name, guest_email, guest_mobile, shipping_address, shipping_city,
    shipping_state, shipping_country, shipping_pincode, items, payment_method, coupon_code } = req.body;

  const order_number = 'THAR-' + Date.now();
  let userId = user_id || null;
  if (!userId && !guest_name) return res.status(400).json({ error: 'Name required' });

  // ✅ SERVER-SIDE PRICE CALCULATION - client ka total nahi maana jayega
  let serverSubtotal = 0;
  const verifiedItems = [];
  for (const item of (items || [])) {
    const product = db.products.find(p => (p.id === item.id || p.id === item.product_id) && p.is_active);
    if (!product) return res.status(400).json({ error: `Product not found: ${item.id}` });
    const qty = parseInt(item.quantity || item.qty) || 1;
    if (qty < 1 || qty > 100) return res.status(400).json({ error: 'Invalid quantity' });
    const price = product.sale_price || product.price; // SERVER se price
    serverSubtotal += price * qty;
    verifiedItems.push({ product, qty, price });
  }

  // ✅ SERVER-SIDE COUPON VERIFICATION
  let serverDiscount = 0;
  let validCoupon = null;
  if (coupon_code) {
    validCoupon = db.coupons.find(c => c.code === coupon_code && c.is_active);
    if (validCoupon) {
      if (validCoupon.min_order && serverSubtotal < validCoupon.min_order)
        return res.status(400).json({ error: `Minimum order ₹${validCoupon.min_order} required` });
      if (validCoupon.max_uses && validCoupon.used_count >= validCoupon.max_uses)
        return res.status(400).json({ error: 'Coupon limit reached' });
      serverDiscount = validCoupon.type === 'percentage'
        ? Math.min(serverSubtotal * validCoupon.value / 100, serverSubtotal)
        : Math.min(validCoupon.value, serverSubtotal);
    }
  }

  const serverShipping = (serverSubtotal - serverDiscount) >= 500 ? 0 : 49;
  const serverTotal = serverSubtotal - serverDiscount + serverShipping;

  const order = {
    id: uuidv4(), order_number, user_id: userId,
    guest_name: guest_name || null, guest_email: guest_email || null,
    guest_mobile: guest_mobile || null, shipping_address, shipping_city,
    shipping_state, shipping_country: shipping_country || 'India', shipping_pincode,
    subtotal: serverSubtotal,       // ✅ Server calculated
    shipping_cost: serverShipping,  // ✅ Server calculated
    tax: 0,
    discount: serverDiscount,       // ✅ Server calculated
    total: serverTotal,             // ✅ Server calculated
    payment_method: payment_method || 'prepaid',
    payment_status: 'pending', payment_id: null, order_status: 'pending',
    tracking_number: null, tracking_link: null, notes: null,
    created_at: new Date().toISOString()
  };
  db.orders.push(order);
  verifiedItems.forEach(({ product, qty, price }) => {
    db.order_items.push({
      id: uuidv4(), order_id: order.id, product_id: product.id,
      product_name: product.name, product_price: price,
      quantity: qty, total: price * qty
    });
  });
  if (validCoupon) validCoupon.used_count = (validCoupon.used_count || 0) + 1;
  saveDB(db);
  res.json({ success: true, order_id: order.id, order_number, verified_total: serverTotal });
});

// ============ USER AUTH MIDDLEWARE ============
const userAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Get user profile
app.get('/api/user/profile', userAuth, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (user) {
    const { password, ...userData } = user;
    res.json(userData);
  } else res.status(404).json({ error: 'User not found' });
});

// Update user profile
app.put('/api/user/profile', userAuth, async (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { name, email, mobile, whatsapp, address, city, state, pincode, dob, gender, current_password, new_password } = req.body;
  if (current_password) {
    const valid = await bcrypt.compare(current_password, user.password);
    if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
    user.password = await bcrypt.hash(new_password, 10);
  }
  if (name) user.name = name;
  if (email !== undefined) user.email = email;
  if (mobile !== undefined) user.mobile = mobile;
  if (whatsapp !== undefined) user.whatsapp = whatsapp;
  if (address !== undefined) user.address = address;
  if (city !== undefined) user.city = city;
  if (state !== undefined) user.state = state;
  if (pincode !== undefined) user.pincode = pincode;
  if (dob !== undefined) user.dob = dob;
  if (gender !== undefined) user.gender = gender;
  saveDB(db);
  res.json({ success: true });
});

// Get user orders
app.get('/api/user/orders', userAuth, (req, res) => {
  const orders = db.orders.filter(o => o.user_id === req.user.id).sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  orders.forEach(o => {
    o.items = db.order_items.filter(i => i.order_id === o.id);
  });
  res.json(orders);
});

// Add product review (only for delivered orders)
app.post('/api/user/review', userAuth, (req, res) => {
  const { product_id, order_id, rating, review_text } = req.body;
  const order = db.orders.find(o => o.id === order_id && o.user_id === req.user.id && o.order_status === 'delivered');
  if (!order) return res.status(400).json({ error: 'Only delivered orders can be reviewed' });
  const existingReview = db.reviews.find(r => r.user_id === req.user.id && r.product_id === product_id && r.order_id === order_id);
  if (existingReview) return res.status(400).json({ error: 'Already reviewed this product for this order' });
  db.reviews.push({
    id: uuidv4(),
    product_id,
    user_id: req.user.id,
    order_id,
    rating,
    review_text,
    is_approved: 1,
    created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// ============ ADMIN ROUTES ============

// Admin login
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const admin = db.admins.find(a => a.username === username && a.is_active);
  if (!admin) return res.status(400).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, admin.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: admin.id, name: admin.name, username: admin.username, role: admin.role, permissions: admin.permissions }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token, admin: { id: admin.id, name: admin.name, username: admin.username, role: admin.role } });
});

// Get dashboard stats
app.get('/api/admin/stats', authMiddleware, (req, res) => {
  const totalOrders = db.orders.length;
  const totalRevenue = db.orders.filter(o => o.payment_status === 'paid').reduce((sum, o) => sum + o.total, 0);
  const totalProducts = db.products.length;
  const totalCustomers = db.users.length;
  const pendingOrders = db.orders.filter(o => o.order_status === 'pending').length;
  const recentOrders = db.orders.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 10);
  res.json({ totalOrders, totalRevenue, totalProducts, totalCustomers, pendingOrders, recentOrders });
});

// Get orders
app.get('/api/admin/orders', authMiddleware, (req, res) => {
  const { status, from_date, to_date, search } = req.query;
  let orders = [...db.orders];

  if (status) orders = orders.filter(o => o.order_status === status);
  if (from_date) orders = orders.filter(o => new Date(o.created_at) >= new Date(from_date));
  if (to_date) orders = orders.filter(o => new Date(o.created_at) <= new Date(to_date));
  if (search) {
    const s = search.toLowerCase();
    orders = orders.filter(o => {
      const user = db.users.find(u => u.id === o.user_id);
      return o.order_number.toLowerCase().includes(s) || (user && user.name.toLowerCase().includes(s)) || (o.guest_mobile && o.guest_mobile.includes(s));
    });
  }

  orders.forEach(o => {
    const user = db.users.find(u => u.id === o.user_id);
    o.customer_name = user ? user.name : o.guest_name;
    o.customer_email = user ? user.email : o.guest_email;
    o.customer_mobile = user ? user.mobile : o.guest_mobile;
    o.items = db.order_items.filter(i => i.order_id === o.id);
  });

  res.json(orders.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Update order status
app.put('/api/admin/orders/:id', authMiddleware, (req, res) => {
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  const { order_status, tracking_number, tracking_link } = req.body;
  if (order_status) order.order_status = order_status;
  if (tracking_number !== undefined) order.tracking_number = tracking_number;
  if (tracking_link !== undefined) order.tracking_link = tracking_link;
  saveDB(db);
  res.json({ success: true });
});

// Get customers
app.get('/api/admin/customers', authMiddleware, (req, res) => {
  const customers = db.users.map(u => {
    const orders = db.orders.filter(o => o.user_id === u.id);
    const totalOrders = orders.length;
    const totalSpent = orders.filter(o => o.payment_status === 'paid').reduce((sum, o) => sum + o.total, 0);
    const { password, ...userData } = u;
    return { ...userData, total_orders: totalOrders, total_spent: totalSpent };
  });
  res.json(customers.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Block/unblock customer
app.put('/api/admin/customers/:id/block', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.is_blocked = req.body.is_blocked ? 1 : 0;
  saveDB(db);
  res.json({ success: true });
});

// Get products
app.get('/api/admin/products', authMiddleware, (req, res) => {
  const { category, search, active } = req.query;
  let products = [...db.products];

  if (category) products = products.filter(p => p.category_id === category);
  if (search) {
    const s = search.toLowerCase();
    products = products.filter(p => p.name.toLowerCase().includes(s) || (p.sku && p.sku.toLowerCase().includes(s)));
  }
  if (active !== undefined) products = products.filter(p => p.is_active === (active === 'true'));

  products.forEach(p => {
    const cat = db.categories.find(c => c.id === p.category_id);
    p.category_name = cat ? cat.name : null;
  });

  res.json(products.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Add product
app.post('/api/admin/products', authMiddleware, checkRole(['super_admin', 'admin']), upload.array('images', 10), (req, res) => {
  const { name, description, short_description, price, sale_price, sku, category_id, inventory, is_featured, is_active } = req.body;
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  const images = req.files ? req.files.map(f => '/uploads/products/' + f.filename) : [];
  const product = {
    id: uuidv4(),
    name,
    slug,
    description: description || null,
    short_description: short_description || null,
    price: parseFloat(price),
    sale_price: sale_price ? parseFloat(sale_price) : null,
    sku: sku || null,
    category_id: category_id || null,
    inventory: parseInt(inventory) || 0,
    images,
    video_url: null,
    is_featured: is_featured === 'true',
    is_active: is_active !== 'false',
    created_at: new Date().toISOString()
  };
  db.products.push(product);
  saveDB(db);
  logActivity(req.admin.id, req.admin.name, 'Product Add', product.name);
  res.json({ success: true });
});

// Update product
app.put('/api/admin/products/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const product = db.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  const { name, description, short_description, price, sale_price, sku, category_id, inventory, is_featured, is_active } = req.body;
  logActivity(req.admin.id, req.admin.name, 'Product Edit', product.name);
  if (name) { product.name = name; product.slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''); }
  if (description !== undefined) product.description = description;
  if (short_description !== undefined) product.short_description = short_description;
  if (price) product.price = parseFloat(price);
  if (sale_price !== undefined) product.sale_price = sale_price ? parseFloat(sale_price) : null;
  if (sku !== undefined) product.sku = sku;
  if (category_id !== undefined) product.category_id = category_id;
  if (inventory !== undefined) product.inventory = parseInt(inventory);
  if (is_featured !== undefined) product.is_featured = is_featured;
  if (is_active !== undefined) product.is_active = is_active;
  saveDB(db);
  res.json({ success: true });
});

// Delete product
app.delete('/api/admin/products/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const idx = db.products.findIndex(p => p.id === req.params.id);
  if (idx > -1) { db.products.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Get categories
app.get('/api/admin/categories', authMiddleware, (req, res) => {
  const categories = db.categories.map(c => {
    const product_count = db.products.filter(p => p.category_id === c.id).length;
    return { ...c, product_count };
  });
  res.json(categories.sort((a,b) => a.name.localeCompare(b.name)));
});

// Add category
app.post('/api/admin/categories', authMiddleware, checkRole(['super_admin']), (req, res) => {
  const { name, description } = req.body;
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  db.categories.push({
    id: uuidv4(), name, slug, description: description || null, image: null,
    is_active: true, created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Delete category
app.delete('/api/admin/categories/:id', authMiddleware, checkRole(['super_admin']), (req, res) => {
  const idx = db.categories.findIndex(c => c.id === req.params.id);
  if (idx > -1) { db.categories.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Get coupons
app.get('/api/admin/coupons', authMiddleware, (req, res) => {
  res.json(db.coupons.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Add coupon
app.post('/api/admin/coupons', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const { code, type, value, min_order, max_uses, valid_from, valid_until } = req.body;
  db.coupons.push({
    id: uuidv4(),
    code: code.toUpperCase(),
    type: type || 'percentage',
    value: parseFloat(value),
    min_order: min_order ? parseFloat(min_order) : null,
    max_uses: max_uses ? parseInt(max_uses) : null,
    used_count: 0,
    valid_from: valid_from || null,
    valid_until: valid_until || null,
    is_active: true,
    created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Delete coupon
app.delete('/api/admin/coupons/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const idx = db.coupons.findIndex(c => c.id === req.params.id);
  if (idx > -1) { db.coupons.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Get inquiries
app.get('/api/admin/inquiries', authMiddleware, (req, res) => {
  const { type, status } = req.query;
  let inquiries = [...db.inquiries];
  if (type) inquiries = inquiries.filter(i => i.type === type);
  if (status) inquiries = inquiries.filter(i => i.status === status);
  res.json(inquiries.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Reply to inquiry
app.put('/api/admin/inquiries/:id/reply', authMiddleware, (req, res) => {
  const inquiry = db.inquiries.find(i => i.id === req.params.id);
  if (!inquiry) return res.status(404).json({ error: 'Inquiry not found' });
  inquiry.reply = req.body.reply;
  inquiry.status = 'replied';
  inquiry.replied_by = req.admin.id;
  saveDB(db);
  res.json({ success: true });
});

// Get dealer inquiries
app.get('/api/admin/dealer-inquiries', authMiddleware, (req, res) => {
  res.json(db.dealer_inquiries.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Get affiliates
app.get('/api/admin/affiliates', authMiddleware, (req, res) => {
  const affiliates = db.affiliates.map(a => {
    const user = db.users.find(u => u.id === a.user_id);
    return { ...a, user_name: user ? user.name : null };
  });
  res.json(affiliates.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Approve/reject affiliate
app.put('/api/admin/affiliates/:id', authMiddleware, (req, res) => {
  const affiliate = db.affiliates.find(a => a.id === req.params.id);
  if (!affiliate) return res.status(404).json({ error: 'Affiliate not found' });
  affiliate.status = req.body.status;
  saveDB(db);
  res.json({ success: true });
});

// Get testimonials
app.get('/api/admin/testimonials', authMiddleware, (req, res) => {
  res.json(db.testimonials.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Add testimonial
app.post('/api/admin/testimonials', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const { name, rating, message } = req.body;
  db.testimonials.push({
    id: uuidv4(), name, rating: parseInt(rating), message,
    is_active: true, created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Delete testimonial
app.delete('/api/admin/testimonials/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const idx = db.testimonials.findIndex(t => t.id === req.params.id);
  if (idx > -1) { db.testimonials.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Get blogs
app.get('/api/admin/blogs', authMiddleware, (req, res) => {
  const blogs = db.blogs.map(b => {
    const author = db.admins.find(a => a.id === b.author_id);
    return { ...b, author_name: author ? author.name : null };
  });
  res.json(blogs.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Add blog
app.post('/api/admin/blogs', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const { title, content, excerpt, image, meta_title, meta_description, status } = req.body;
  // ✅ FIX: Basic XSS check - script tags strip karo blog content se
  const safeContent = (content || '').replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                                      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
  const published_at = status === 'published' ? new Date().toISOString() : null;
  db.blogs.push({
    id: uuidv4(),
    title, slug, content: safeContent, excerpt: sanitize(excerpt || ''), image,
    meta_title, meta_description,
    status: status || 'draft',
    author_id: req.admin.id,
    created_at: new Date().toISOString(),
    published_at
  });
  saveDB(db);
  res.json({ success: true });
});

// Update blog
app.put('/api/admin/blogs/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const blog = db.blogs.find(b => b.id === req.params.id);
  if (!blog) return res.status(404).json({ error: 'Blog not found' });
  const { title, content, excerpt, image, meta_title, meta_description, status } = req.body;
  if (title) blog.title = title;
  if (content !== undefined) blog.content = content;
  if (excerpt !== undefined) blog.excerpt = excerpt;
  if (image !== undefined) blog.image = image;
  if (meta_title !== undefined) blog.meta_title = meta_title;
  if (meta_description !== undefined) blog.meta_description = meta_description;
  if (status) { blog.status = status; blog.published_at = status === 'published' ? new Date().toISOString() : null; }
  saveDB(db);
  res.json({ success: true });
});

// Delete blog
app.delete('/api/admin/blogs/:id', authMiddleware, checkRole(['super_admin', 'admin']), (req, res) => {
  const idx = db.blogs.findIndex(b => b.id === req.params.id);
  if (idx > -1) { db.blogs.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Get settings
app.get('/api/admin/settings', authMiddleware, (req, res) => {
  res.json(db.settings);
});

// Update settings (super admin only)
app.put('/api/admin/settings', authMiddleware, checkRole(['super_admin']), (req, res) => {
  db.settings = { ...db.settings, ...req.body };
  saveDB(db);
  res.json({ success: true });
});

// Upload logo
app.post('/api/admin/settings/logo', authMiddleware, checkRole(['super_admin']), logoUpload.single('logo'), (req, res) => {
  if (req.file) {
    db.settings.site_logo = '/img/logo' + path.extname(req.file.originalname);
    saveDB(db);
    res.json({ success: true, logo: db.settings.site_logo });
  } else {
    res.status(400).json({ error: 'No file uploaded' });
  }
});

// Get SEO settings
app.get('/api/admin/seo', authMiddleware, (req, res) => {
  res.json(db.seo_settings);
});

// Update SEO settings
app.put('/api/admin/seo', authMiddleware, checkRole(['super_admin']), (req, res) => {
  db.seo_settings = { ...db.seo_settings, ...req.body };
  saveDB(db);
  res.json({ success: true });
});

// Get admins
app.get('/api/admin/admins', authMiddleware, checkRole(['super_admin']), (req, res) => {
  const admins = db.admins.map(a => ({ id: a.id, name: a.name, username: a.username, role: a.role, is_active: a.is_active, created_at: a.created_at }));
  res.json(admins);
});

// Add admin
app.post('/api/admin/admins', authMiddleware, checkRole(['super_admin']), async (req, res) => {
  const { name, username, password, role, permissions } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.admins.push({
    id: uuidv4(), name, username, password: hashedPassword, role: role || 'admin',
    permissions: permissions || {}, created_by: req.admin.id, is_active: true, created_at: new Date().toISOString()
  });
  saveDB(db);
  res.json({ success: true });
});

// Delete admin
app.delete('/api/admin/admins/:id', authMiddleware, checkRole(['super_admin']), (req, res) => {
  if (req.params.id === req.admin.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  const idx = db.admins.findIndex(a => a.id === req.params.id);
  if (idx > -1) { db.admins.splice(idx, 1); saveDB(db); }
  res.json({ success: true });
});

// Activity log storage (in-memory + DB)
if (!global.activityLog) global.activityLog = [];

function logActivity(adminId, adminName, action, details) {
  const entry = {
    id: uuidv4(),
    admin_id: adminId,
    admin_name: adminName,
    action,
    details: details || '',
    timestamp: new Date().toISOString()
  };
  if (!global.activityLog) global.activityLog = [];
  global.activityLog.unshift(entry);
  if (global.activityLog.length > 500) global.activityLog = global.activityLog.slice(0, 500);
}

// Get activity log
app.get('/api/admin/activity', authMiddleware, checkRole(['super_admin']), (req, res) => {
  res.json(global.activityLog || []);
});

// Get all orders for super admin dashboard (detailed)
app.get('/api/admin/orders/dashboard', authMiddleware, checkRole(['super_admin']), (req, res) => {
  const orders = db.orders.map(o => {
    const user = db.users.find(u => u.id === o.user_id);
    return {
      ...o,
      customer_name: user ? user.name : o.guest_name,
      country: user?.country || 'India',
      customer_state: user?.state || o.shipping_state,
      customer_city: user?.city || o.shipping_city
    };
  });
  res.json(orders.sort((a,b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Customer dashboard data
app.get('/api/admin/customers/dashboard', authMiddleware, checkRole(['super_admin']), (req, res) => {
  const customers = db.users.map(u => {
    const orders = db.orders.filter(o => o.user_id === u.id);
    const returnCount = orders.filter(o => o.order_status === 'returned').length;
    const totalSpent = orders.filter(o => o.payment_status === 'paid').reduce((sum, o) => sum + o.total, 0);
    const { password, ...userData } = u;
    return { ...userData, order_count: orders.length, total_spent: totalSpent, return_count: returnCount };
  });
  res.json(customers);
});

// Serve static files
app.use(express.static('.'));

app.listen(PORT, () => {
  console.log(`Thar Oil server running on http://localhost:${PORT}`);
});