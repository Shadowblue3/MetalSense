const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
require('dotenv').config();
const http = require('http');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const FLASK_URL = process.env.FLASK_URL || 'https://metalsense-backend.onrender.com';
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const fs = require('fs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

// Research uploads (PDF)
const uploadDir = path.join(__dirname, 'public', 'uploads', 'research');
try { fs.mkdirSync(uploadDir, { recursive: true }); } catch (e) {}
const storagePdf = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const name = String(file.originalname || 'file.pdf').replace(/\s+/g, '_');
    cb(null, unique + '-' + name);
  }
});
const uploadPdf = multer({
  storage: storagePdf,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') return cb(null, true);
    cb(new Error('Only PDF files are allowed'));
  },
  limits: { fileSize: 15 * 1024 * 1024 }
});

// Separate temp storage for image uploads
const tmpDir = path.join(__dirname, 'public', 'uploads', 'tmp');
try { fs.mkdirSync(tmpDir, { recursive: true }); } catch (e) {}
const storageImg = multer.diskStorage({
  destination: tmpDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safe = String(file.originalname || 'image').replace(/\s+/g, '_');
    cb(null, unique + '-' + safe);
  }
});
const uploadImg = multer({
  storage: storageImg,
  fileFilter: (req, file, cb) => {
    if (file && typeof file.mimetype === 'string' && file.mimetype.startsWith('image/')) return cb(null, true);
    cb(new Error('Only image files are allowed'));
  },
  limits: { fileSize: 8 * 1024 * 1024 }
});

// Configure Cloudinary (values taken from .env)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// HTTP keep-alive agents and simple in-memory caches for Flask proxies
const keepAliveHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 20, maxFreeSockets: 10, keepAliveMsecs: 10000 });
const keepAliveHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: 20, maxFreeSockets: 10, keepAliveMsecs: 10000 });

// Plot (PNG) cache and inflight dedupe
const plotCache = new Map(); // key -> { buf: Buffer, ts: number }
const inflightPlot = new Map(); // key -> Promise<Buffer>
const PLOT_TTL_MS = Number(process.env.PLOT_CACHE_TTL_MS || 3 * 60 * 1000); // 3 minutes

// Map (HTML) cache and inflight dedupe
const mapCache = new Map(); // key -> { html: string, ts: number }
const inflightMap = new Map(); // key -> Promise<string>
const MAP_TTL_MS = Number(process.env.MAP_CACHE_TTL_MS || 5 * 60 * 1000); // 5 minutes

// Analysis JSON cache to reduce repeated heavy calls
const analysisCache = new Map(); // key(query) -> { payload: any, ts: number }
const ANALYSIS_TTL_MS = Number(process.env.ANALYSIS_CACHE_TTL_MS || 2 * 60 * 1000); // 2 minutes

// Helper: Send email via SendGrid HTTP API (avoids SMTP connectivity issues on PaaS)
async function sendViaSendGrid({ from, to, subject, text, html, apiKey, timeoutMs = 15000 }) {
  return await new Promise((resolve, reject) => {
    try {
      const body = {
        personalizations: [
          {
            to: [{ email: to }],
          },
        ],
        from: { email: from },
        subject,
        content: [{ type: 'text/plain', value: text || '' }],
      };

      if (html) {
        body.content.push({ type: 'text/html', value: html });
      }

      const payload = JSON.stringify(body);

      const req = https.request(
        'https://api.sendgrid.com/v3/mail/send',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: timeoutMs,
        },
        (resp) => {
          let data = '';
          resp.on('data', (c) => (data += c.toString()));
          resp.on('end', () => {
            if (resp.statusCode === 202) {
              resolve({ ok: true });
            } else {
              console.error('SendGrid API error', resp.statusCode, data);
              reject(new Error(`sendgrid_http_${resp.statusCode}`));
            }
          });
        }
      );

      req.on('error', (err) => reject(err));
      req.on('timeout', () => {
        try { req.destroy(); } catch (_) {}
        reject(new Error('sendgrid_timeout'));
      });
      req.write(payload);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

// Hardcoded Master credentials (override via env if provided)
const MASTER_ID = process.env.MASTER_ID;
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;

// Middleware
app.set('trust proxy', 1);
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 2 * 60 * 60 * 1000, // 2 hours
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Set EJS as template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

const generalModel = require("./models/general-public")
const officialModel = require("./models/officials")
const postModel = require('./models/post');
const communicationModel = require('./models/communication');
const dbConnection = require("./config/db");
const dataModel = require('./models/dataModel');
const governmentModel = require('./models/government');
const researcherModel = require('./models/researcher');
const ngoModel = require('./models/ngo');
const researchPostModel = require('./models/researchPost');
const heavySampleModel = require('./models/heavySample');
const policyModel = require('./models/policy');
const ngoTaskModel = require('./models/ngoTask');

// Mock data for demonstration
const mockData = {
  stats: {
    totalCases: 847,
    activeAlerts: 23,
    waterSources: 156,
    riskLevel: 'Medium'
  },
  alerts: [
    {
      id: 1,
      type: 'outbreak',
      severity: 'high',
      title: 'Cholera Outbreak Detected',
      location: 'Guwahati East District',
      affectedCount: 23,
      time: '2 hours ago',
      status: 'active'
    },
    {
      id: 2,
      type: 'water',
      severity: 'medium',
      title: 'Water Quality Alert',
      location: 'Silchar Community Well',
      affectedCount: 0,
      time: '5 hours ago',
      status: 'investigating'
    },
    {
      id: 3,
      type: 'prediction',
      severity: 'low',
      title: 'Predicted Outbreak Risk',
      location: 'Dibrugarh Region',
      affectedCount: 0,
      time: '1 day ago',
      status: 'monitoring'
    }
  ],
  waterSensors: [
    {
      id: '1',
      location: 'Village Well A',
      pH: 7.2,
      turbidity: 3.1,
      bacterial: 'safe',
      lastUpdated: new Date().toLocaleString(),
      status: 'online'
    },
    {
      id: '2',
      location: 'River Point B',
      pH: 6.8,
      turbidity: 8.5,
      bacterial: 'moderate',
      lastUpdated: new Date().toLocaleString(),
      status: 'online'
    },
    {
      id: '3',
      location: 'Community Pond C',
      pH: 6.2,
      turbidity: 15.2,
      bacterial: 'high',
      lastUpdated: new Date().toLocaleString(),
      status: 'offline'
    }
  ]
};
app.use((req, res, next) => {
  res.locals.language = req.query.lang || 'en';
  res.locals.user = req.session.user || null;
  next();
});
// Auth helpers
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.session.user || !roles.includes(req.session.user.role)) {
      return res.redirect('/dashboard');
    }
    next();
  };
}

// Routes
app.get('/', (req, res) => {
  const language = req.query.lang || 'en';
  res.render('landing', { layout: false, activeTab: 'landing' });
});

// Health checks
app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const language = req.query.lang || 'en';

    // Compute total cases as number of JSON documents in Disease_Data
    const totalCases = await dataModel.countDocuments({});

    const role = req.session.user && req.session.user.role;

    if (role === 'general') {
      const [totalPosts, activeUsers] = await Promise.all([
        postModel.countDocuments({}),
        generalModel.countDocuments({})
      ]);
      const stats = { totalCases, totalPosts, activeUsers };
      return res.render('publicDashboard', {
        title: 'Public Map',
        language,
        activeTab: 'dashboard',
        alerts: [],
        stats
      });
    }

    if (role === 'master') {
      const [totalPosts, assignedCount, unassignedCount] = await Promise.all([
        postModel.countDocuments({}),
        postModel.countDocuments({ assignedOfficerId: { $ne: null } }),
        postModel.countDocuments({ $or: [ { assignedOfficerId: null }, { assignedOfficerId: { $exists: false } } ] })
      ]);
      const stats = { totalCases, totalPosts, assignedCount, unassignedCount };
      return res.render('dashboard', {
        title: 'Admin Map',
        language,
        stats,
        alerts: [],
        activeTab: 'dashboard'
      });
    }

    if (role === 'official') {
      const me = String(req.session.user && req.session.user.employeeId || '');
      const assignedToMe = await postModel.countDocuments({ assignedOfficerId: me });
      const stats = { totalCases, assignedToMe };
      return res.render('dashboard', {
        title: 'Admin Map',
        language,
        stats,
        alerts: [],
        activeTab: 'dashboard'
      });
    }

    // Default fallback for other roles (researcher/government/ngo)
    const stats = { totalCases };
    return res.render('dashboard', {
      title: 'Admin Map',
      language,
      stats,
      alerts: [],
      activeTab: 'dashboard'
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    const language = req.query.lang || 'en';
    // Provide safe fallback stats
    const stats = { totalCases: 0, totalPosts: 0, activeUsers: 0, assignedCount: 0, unassignedCount: 0, assignedToMe: 0 };
    // Render according to role context, defaulting to admin view
    if (req.session.user && req.session.user.role === 'general') {
      return res.render('publicDashboard', {
        title: 'Public Map',
        language,
        activeTab: 'dashboard',
        alerts: [],
        stats
      });
    }
    return res.render('dashboard', {
      title: 'Dashboard',
      language,
      stats,
      alerts: [],
      activeTab: 'dashboard'
    });
  }
});

app.get('/report', requireLogin, requireRole(['general']), (req, res) => {
  const language = req.query.lang || 'en';
  res.render('report', {
    title: 'Community Report',
    language,
    activeTab: 'report'
  });
});

app.post('/report', requireLogin, requireRole(['general']), uploadImg.single('image'), async (req, res) => {
  const language = req.query.lang || 'en';
  try {
    const { title, region, body, symptoms, type, waterSource, affectedCount, latitude, longitude } = req.body;

    let imageUrl = undefined;
    const file = req.file;
    if (file && file.path) {
      try {
        const result = await cloudinary.uploader.upload(file.path, {
          folder: 'metalsense/community-posts',
          resource_type: 'image',
          use_filename: true,
          unique_filename: true,
          overwrite: false
        });
        imageUrl = result && result.secure_url ? result.secure_url : result.url;
      } catch (e) {
        console.error('Cloudinary upload failed:', e);
      } finally {
        try { fs.unlinkSync(file.path); } catch (_) {}
      }
    }

    const post = new postModel({
      title: title,
      region: region,
      body: body,
      symptoms: symptoms,
      type: type,
      waterSource: waterSource,
      affectedCount: affectedCount,
      imageUrl: imageUrl || undefined,
      latitude: latitude ? Number(latitude) : undefined,
      longitude: longitude ? Number(longitude) : undefined
    });

    await post.save();

    return res.render('report', {
      title: 'Community Report',
      language,
      activeTab: 'report',
      success: true,
      message: 'Report submitted successfully! Health officials have been notified.'
    });
  } catch (err) {
    console.error('report post error', err);
    return res.render('report', {
      title: 'Community Report',
      language,
      activeTab: 'report',
      success: false,
      message: 'Failed to submit report. Please try again.'
    });
  }
});

app.get('/water-quality', requireLogin, requireRole(['official', 'master']), (req, res) => {
  const language = req.query.lang || 'en';
  res.render('water-quality', {
    title: 'Water Quality',
    language,
    sensors: mockData.waterSensors,
    activeTab: 'water'
  });
});

app.get('/education', requireLogin, requireRole(['general']), (req, res) => {
  const language = req.query.lang || 'en';
  const module = req.query.module || 'hygiene';
  res.render('education', {
    title: 'Education',
    language,
    activeModule: module,
    activeTab: 'education'
  });
});

// API endpoints for AJAX requests
app.get('/api/alerts', (req, res) => {
  res.json(mockData.alerts);
});

app.get('/api/stats', (req, res) => {
  res.json(mockData.stats);
});

app.get('/api/water-sensors', (req, res) => {
  res.json(mockData.waterSensors);
});

// Translation API (server-side, uses Google Translate)
const SUPPORTED_LANGS = ['en', 'hi', 'as', 'bn'];
const translationCache = new Map();

function translateViaGoogle(texts, target, source = 'en') {
  return new Promise((resolve) => {
    try {
      const key = process.env.GOOGLE_TRANSLATE_API_KEY;
      if (!key) {
        return resolve([]);
      }
      const url = new URL('https://translation.googleapis.com/language/translate/v2');
      url.searchParams.set('key', key);

      const payload = JSON.stringify({ q: texts, target, source });

      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 20000
      };

      const req = https.request(url, options, (resp) => {
        let data = '';
        resp.on('data', (chunk) => { data += chunk.toString(); });
        resp.on('end', () => {
          try {
            const json = JSON.parse(data);
            const out = (json && json.data && Array.isArray(json.data.translations))
              ? json.data.translations.map(t => t.translatedText)
              : [];
            resolve(out);
          } catch (e) {
            console.error('translate parse error', e);
            console.error('Raw response:', data);
            resolve([]);
          }
        });
      });

      req.on('error', (err) => {
        console.error('translate request error', err);
        resolve([]);
      });

      req.on('timeout', () => {
        try { req.destroy(); } catch (_) {}
        resolve([]);
      });

      req.write(payload);
      req.end();
    } catch (e) {
      console.error('translateViaGoogle error', e);
      resolve([]);
    }
  });
}

app.post('/api/translate', async (req, res) => {
  try {
    const { q, target = 'en', source = 'en' } = req.body || {};

    if (!process.env.GOOGLE_TRANSLATE_API_KEY) {
      return res.status(501).json({ error: 'translate_unconfigured' });
    }

    if (!q) return res.json({ translations: [] });
    if (!SUPPORTED_LANGS.includes(target)) {
      return res.status(400).json({ error: 'unsupported_language' });
    }

    const arr = Array.isArray(q) ? q.map(s => String(s)) : [String(q)];

    if (target === source || target === 'en') {
      return res.json({ translations: arr });
    }

    const results = new Array(arr.length);
    const toTranslate = [];
    const mapIndex = [];

    arr.forEach((text, idx) => {
      const key = `${source}|${target}|${text}`;
      if (translationCache.has(key)) {
        results[idx] = translationCache.get(key);
      } else {
        toTranslate.push(text);
        mapIndex.push(idx);
      }
    });

    if (toTranslate.length) {
      const translated = await translateViaGoogle(toTranslate, target, source);
      translated.forEach((t, j) => {
        const idx = mapIndex[j];
        results[idx] = t;
        const k = `${source}|${target}|${toTranslate[j]}`;
        translationCache.set(k, t);
      });
    }

    for (let i = 0; i < results.length; i++) {
      if (typeof results[i] === 'undefined' || results[i] === null) {
        results[i] = arr[i];
      }
    }

    res.json({ translations: results });
  } catch (err) {
    console.error('translate api error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

// Disease data APIs

// Heavy metal sampling map API
// Returns points with coordinates and selected chemistry for public/admin map
app.get('/api/heavy-samples', async (req, res) => {
  try {
    const year = req.query.year ? Number(req.query.year) : undefined;
    const month = req.query.month ? Number(req.query.month) : undefined;

    const filter = { latitude: { $ne: null }, longitude: { $ne: null } };
    if (!Number.isNaN(year) && typeof year === 'number') filter.year = year;
    if (!Number.isNaN(month) && typeof month === 'number') filter.month = month;

    const fields = {
      sample_id: 1,
      location: 1,
      latitude: 1,
      longitude: 1,
      year: 1,
      month: 1,
      pH: 1,
      EC: 1,
      As: 1, Cd: 1, Cr: 1, Cu: 1, Pb: 1, Zn: 1, Ni: 1,
      Background_As: 1, Background_Cd: 1, Background_Cr: 1, Background_Cu: 1, Background_Pb: 1, Background_Zn: 1, Background_Ni: 1,
      _id: 0,
    };

    const docs = await heavySampleModel.find(filter, fields).lean();

    const points = (docs || []).map(d => ({
      sample_id: d.sample_id,
      location: d.location,
      lat: typeof d.latitude === 'number' ? d.latitude : Number(d.latitude),
      lon: typeof d.longitude === 'number' ? d.longitude : Number(d.longitude),
      year: d.year,
      month: d.month,
      pH: d.pH,
      EC: d.EC,
      metals: {
        As: d.As, Cd: d.Cd, Cr: d.Cr, Cu: d.Cu, Pb: d.Pb, Zn: d.Zn, Ni: d.Ni,
      },
      background: {
        As: d.Background_As, Cd: d.Background_Cd, Cr: d.Background_Cr, Cu: d.Background_Cu, Pb: d.Background_Pb, Zn: d.Background_Zn, Ni: d.Background_Ni,
      }
    })).filter(p => typeof p.lat === 'number' && typeof p.lon === 'number' && !Number.isNaN(p.lat) && !Number.isNaN(p.lon));

    res.json({ success: true, count: points.length, points });
  } catch (e) {
    console.error('heavy-samples api error:', e);
    res.status(500).json({ success: false, points: [] });
  }
});
// Admin (official) Update Data pages and APIs for Heavy Samples
app.get('/update-data', requireLogin, requireRole(['official']), async (req, res) => {
  const language = req.query.lang || 'en';
  res.render('update-data', {
    title: 'Update Data',
    language,
    activeTab: 'update-data'
  });
});

function toNumberOrNull(v) {
  const n = Number(v);
  return (typeof n === 'number' && !Number.isNaN(n)) ? n : undefined;
}

app.get('/api/heavy-samples/search', requireLogin, requireRole(['official']), async (req, res) => {
  try {
    const { location, year, month, limit } = req.query;
    const filter = {};
    if (location) {
      filter.location = { $regex: String(location), $options: 'i' };
    }
    if (year) filter.year = Number(year);
    if (month) filter.month = Number(month);
    const max = Math.min(200, Number(limit || 100));
    const docs = await heavySampleModel.find(filter).sort({ updatedAt: -1 }).limit(max).lean();
    res.json({ success: true, list: docs });
  } catch (e) {
    console.error('heavy-samples search error:', e);
    res.status(500).json({ success: false, list: [] });
  }
});

app.post('/api/heavy-samples', requireLogin, requireRole(['official']), async (req, res) => {
  try {
    const body = req.body || {};
    const doc = new heavySampleModel({
      sample_id: toNumberOrNull(body.sample_id),
      location: body.location || undefined,
      latitude: toNumberOrNull(body.latitude),
      longitude: toNumberOrNull(body.longitude),
      year: toNumberOrNull(body.year),
      month: toNumberOrNull(body.month),
      pH: toNumberOrNull(body.pH),
      EC: toNumberOrNull(body.EC),
      As: toNumberOrNull(body.As),
      Cd: toNumberOrNull(body.Cd),
      Cr: toNumberOrNull(body.Cr),
      Cu: toNumberOrNull(body.Cu),
      Pb: toNumberOrNull(body.Pb),
      Zn: toNumberOrNull(body.Zn),
      Ni: toNumberOrNull(body.Ni),
      Background_As: toNumberOrNull(body.Background_As),
      Background_Cd: toNumberOrNull(body.Background_Cd),
      Background_Cr: toNumberOrNull(body.Background_Cr),
      Background_Cu: toNumberOrNull(body.Background_Cu),
      Background_Pb: toNumberOrNull(body.Background_Pb),
      Background_Zn: toNumberOrNull(body.Background_Zn),
      Background_Ni: toNumberOrNull(body.Background_Ni),
    });
    await doc.save();
    res.json({ success: true, doc });
  } catch (e) {
    console.error('heavy-samples create error:', e);
    res.status(500).json({ success: false, message: 'create_failed' });
  }
});

app.put('/api/heavy-samples/:id', requireLogin, requireRole(['official']), async (req, res) => {
  try {
    const id = req.params.id;
    const body = req.body || {};
    const set = {};
    const assign = (k, v) => { if (typeof v !== 'undefined') set[k] = v; };
    assign('sample_id', toNumberOrNull(body.sample_id));
    assign('location', body.location || undefined);
    assign('latitude', toNumberOrNull(body.latitude));
    assign('longitude', toNumberOrNull(body.longitude));
    assign('year', toNumberOrNull(body.year));
    assign('month', toNumberOrNull(body.month));
    assign('pH', toNumberOrNull(body.pH));
    assign('EC', toNumberOrNull(body.EC));
    ['As','Cd','Cr','Cu','Pb','Zn','Ni'].forEach(k => assign(k, toNumberOrNull(body[k])));
    ['Background_As','Background_Cd','Background_Cr','Background_Cu','Background_Pb','Background_Zn','Background_Ni'].forEach(k => assign(k, toNumberOrNull(body[k])));
    const updated = await heavySampleModel.findByIdAndUpdate(id, { $set: set }, { new: true });
    if (!updated) return res.status(404).json({ success: false, message: 'not_found' });
    res.json({ success: true, doc: updated });
  } catch (e) {
    console.error('heavy-samples update error:', e);
    res.status(500).json({ success: false, message: 'update_failed' });
  }
});

app.get('/api/disease/months', async (req, res) => {
  try {
    const months = await dataModel.distinct('mon');
    const sorted = (months || []).filter(m => m != null).sort((a, b) => a - b);
    const latestMonth = sorted.length ? sorted[sorted.length - 1] : null;
    res.json({ months: sorted, latestMonth });
  } catch (err) {
    console.error('months api error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/api/disease/hotspots', async (req, res) => {
  try {
    let mon = req.query.mon ? Number(req.query.mon) : null;
    const year = req.query.year ? Number(req.query.year) : null;

    const match = {};
    if (year) match.year = year;
    if (mon) {
      match.mon = mon;
    } else {
      // default to latest month available if none provided
      const months = await dataModel.distinct('mon');
      const sorted = (months || []).filter(m => m != null).sort((a, b) => a - b);
      mon = sorted.length ? sorted[sorted.length - 1] : null;
      if (mon) match.mon = mon;
    }

    const docs = await dataModel.find(match, {
      state_ut: 1,
      district: 1,
      Disease: 1,
      Cases: 1,
      Latitude: 1,
      Longitude: 1,
      _id: 0
    }).lean();

    const hotspots = (docs || [])
      .filter(d => typeof d.Latitude === 'number' && typeof d.Longitude === 'number')
      .map(d => ({
        state_ut: d.state_ut || '',
        district: d.district || '',
        Disease: d.Disease || '',
        Cases: Number(d.Cases || 0),
        lat: d.Latitude,
        lon: d.Longitude
      }));

    res.json({ month: mon, year: match.year || null, hotspots });
  } catch (err) {
    console.error('hotspots api error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/api/disease/trends', async (req, res) => {
  try {
    // If year is provided, filter by that year; otherwise aggregate across all years
    const year = req.query.year ? Number(req.query.year) : null;

    const pipeline = [];
    if (year) pipeline.push({ $match: { year } });
    pipeline.push({ $group: { _id: '$mon', total: { $sum: { $ifNull: ['$Cases', 0] } } } });

    const result = await dataModel.aggregate(pipeline);
    const totalsByMonth = new Map(result.map(r => [Number(r._id), r.total]));
    const monthly = Array.from({ length: 12 }, (_, i) => ({ mon: i + 1, total: totalsByMonth.get(i + 1) || 0 }));

    res.json({ year, monthly });
  } catch (err) {
    console.error('trends api error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/api/disease/summary', async (req, res) => {
  try {
    const agg = await dataModel.aggregate([
      {
        $group: {
          _id: null,
          totalCases: { $sum: { $ifNull: ['$Cases', 0] } },
          totalDeaths: { $sum: { $ifNull: ['$Deaths', 0] } },
          minYear: { $min: '$year' },
          maxYear: { $max: '$year' }
        }
      }
    ]);

    const { totalCases = 0, totalDeaths = 0, minYear = null, maxYear = null } = agg[0] || {};
    const months = await dataModel.distinct('mon');
    const sortedMonths = (months || []).filter(m => m != null).sort((a, b) => a - b);

    res.json({ totalCases, totalDeaths, yearRange: { min: minYear, max: maxYear }, months: sortedMonths });
  } catch (err) {
    console.error('summary api error:', err);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { layout: false, activeTab: "login" })
})

app.get('/signup', (req, res) => {
  res.render('signup', { layout: false, activeTab: "login" })
})

app.post('/signup', async (req, res) => {
  try {
    const { userType } = req.body;
    const saltRounds = 10;

    if (!userType || (userType !== 'public' && userType !== 'government')) {
      return res.status(403).send('Only public or government signup is allowed');
    }

    if (userType === 'public') {
      const { fullName, mobile, email, state, district, village, password } = req.body;

      // Check existing (by email if provided)
      if (email) {
        const existing = await generalModel.findOne({ userEmail: email });
        if (existing) {
          return res.status(409).send('Account already exists with this email');
        }
      }

      const hashed = await bcrypt.hash(password, saltRounds);
      const doc = new generalModel({
        name: fullName,
        phoneNo: mobile ? Number(mobile) : undefined,
        userEmail: email || undefined,
        state,
        district,
        Area: village,
        password: hashed
      });
      await doc.save();
      return res.redirect('/login');
    }

    // Government signup
    if (userType === 'government') {
      const { email, mobile, state, district, password, confirmPassword } = req.body;
      if (!email || !mobile || !state || !district || !password || !confirmPassword) {
        return res.status(400).send('Missing required fields');
      }
      if (String(password) !== String(confirmPassword)) {
        return res.status(400).send('Passwords do not match');
      }
      const mobileRegex = /^[6-9]\d{9}$/;
      if (!mobileRegex.test(String(mobile))) {
        return res.status(400).send('Invalid mobile number');
      }

      const exists = await governmentModel.findOne({ email });
      if (exists) return res.status(409).send('Government account already exists with this email');

      // Generate unique GOV ID
      function genGovId() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        let s = 'GOV';
        for (let i = 0; i < 6; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
        return s;
      }
      let newId = null;
      for (let i = 0; i < 6; i++) {
        const candidate = genGovId();
        const clash = await governmentModel.findOne({ id: candidate });
        if (!clash) { newId = candidate; break; }
      }
      if (!newId) return res.status(500).send('Failed to generate unique ID');

      const hashed = await bcrypt.hash(password, saltRounds);
      const gov = new governmentModel({
        email,
        id: newId,
        phone: Number(mobile),
        state: state || undefined,
        district: district || undefined,
        password: hashed,
      });
      await gov.save();
      return res.redirect('/login?govId=' + encodeURIComponent(newId));
    }
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).send('Internal server error');
  }
});

app.get('/outbreak-prediction', requireLogin, async (req, res) => {
  const language = req.query.lang || 'en';

  // If this is an initial request (non-AJAX), render a loader page first
  if (!req.xhr && req.headers.accept && req.headers.accept.includes('text/html') && !req.query.ready) {
    return res.render('prediction-loader', {
      layout: false,
      title: 'Predicting Outbreak',
      language,
      activeTab: 'prediction'
    });
  }

  // Replace the fetchFromFlask function in your server.js with this improved version

async function fetchFromFlask() {
  const base = (process.env.FLASK_URL || FLASK_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');
  const url = base + '/api/predict';
  
  return await new Promise((resolve) => {
    const lib = url.startsWith('https') ? https : http;
    
    const options = {
      timeout: 30000, // Increased timeout to 30 seconds
      headers: { 
        'Accept': 'application/json',
        'Connection': 'keep-alive',
        'User-Agent': 'AquaFlow-Node-Client/1.0'
      }
    };
    
    let timeoutId;
    let requestAborted = false;
    
    const req = lib.get(url, options, (resp) => {
      // Clear timeout once we get a response
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      let data = '';
      
      resp.on('data', (chunk) => { 
        data += chunk.toString(); 
      });
      
      resp.on('end', () => {
        if (requestAborted) return;
        
        try {
          const json = JSON.parse(data);
          resolve(json && typeof json === 'object' ? json : { redzones: [], mapPath: null });
        } catch (e) {
          console.error('Flask JSON parse error:', e);
          console.error('Raw response:', data);
          resolve({ redzones: [], mapPath: null });
        }
      });
      
      resp.on('error', (err) => {
        if (requestAborted) return;
        console.error('Flask response error:', err);
        resolve({ redzones: [], mapPath: null });
      });
      
      resp.on('close', () => {
        if (requestAborted) return;
        if (!data) {
          console.error('Flask connection closed without data');
          resolve({ redzones: [], mapPath: null });
        }
      });
    });
    
    // Set up timeout handler
    timeoutId = setTimeout(() => {
      requestAborted = true;
      console.error('Flask request timeout after 30 seconds');
      try { 
        req.destroy(); 
      } catch(e) {
        console.error('Error destroying request:', e);
      }
      resolve({ redzones: [], mapPath: null });
    }, 30000);
    
    req.on('error', (err) => {
      if (requestAborted) return;
      requestAborted = true;
      
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      console.error('Flask request error:', err);
      
      // Handle specific error types
      if (err.code === 'ECONNRESET' || err.code === 'ENOTFOUND' || err.code === 'ETIMEDOUT') {
        console.error('Connection issue with Flask server. Please check if Flask is running and accessible.');
      }
      
      resolve({ redzones: [], mapPath: null });
    });
    
    req.on('timeout', () => {
      if (requestAborted) return;
      requestAborted = true;
      
      console.error('Flask request timeout');
      try { 
        req.destroy(); 
      } catch(e) {
        console.error('Error destroying timed out request:', e);
      }
      resolve({ redzones: [], mapPath: null });
    });
    
    // Set socket timeout
    req.setTimeout(30000);
    
    req.end();
  });
}

  const payload = await fetchFromFlask();

  res.render('outbreak-prediction', {
    title: 'Outbreak Prediction',
    language,
    activeTab: 'prediction',
    alerts: mockData.alerts,
    redzones: payload.redzones || [],
    mapPath: payload.mapPath || null
  });
});

app.get('/community-post', requireLogin, requireRole(['official', 'master']), async (req, res) => {
  const language = req.query.lang || 'en';

  const pipelineBase = [
    {
      $addFields: {
        priority: {
          $cond: [
            {
              $gt: [
                {
                  $size: {
                    $filter: {
                      input: { $ifNull: ['$symptoms', []] },
                      as: 'symp',
                      cond: { $in: ['$symp', ['diarrhea', 'vomiting']] }
                    }
                  }
                },
                0
              ]
            },
            1,
            0
          ]
        },
        affectedCountNum: {
          $convert: { input: '$affectedCount', to: 'int', onError: 0, onNull: 0 }
        }
      }
    },
    { $sort: { priority: -1, affectedCountNum: -1, _id: -1 } }
  ];

  const isMaster = req.session.user && req.session.user.role === 'master';

  let thePosts = [];
  if (isMaster) {
    thePosts = await postModel.aggregate(pipelineBase);
  } else {
    const officerId = String(req.session.user && req.session.user.employeeId || '');
    thePosts = await postModel.aggregate([
      { $match: { assignedOfficerId: officerId } },
      ...pipelineBase
    ]);
  }

  const mapPosts = thePosts;

  res.render('community-post', {
    title: 'Community Post',
    language,
    activeTab: 'community-post',
    thePosts,
    mapPosts,
    isMaster
  });
});

// Toggle resolved status
app.post('/community-post/:id/toggle', requireLogin, requireRole(['official', 'master']), async (req, res) => {
  try {
    const id = req.params.id;
    const { resolved } = req.body; // boolean or string 'true'/'false'
    const newVal = typeof resolved === 'string' ? resolved === 'true' : !!resolved;
    await postModel.findByIdAndUpdate(id, { $set: { resolved: newVal } });
    return res.json({ success: true });
  } catch (err) {
    console.error('toggle resolved error', err);
    return res.status(500).json({ success: false });
  }
});

// Assign or unassign a post to an officer (Master only)
app.post('/community-post/:id/assign', requireLogin, requireRole(['master']), async (req, res) => {
  try {
    const id = req.params.id;
    let { officerId } = req.body;

    if (officerId === '' || officerId === null || typeof officerId === 'undefined') {
      await postModel.findByIdAndUpdate(id, { $set: { assignedOfficerId: null } });
      return res.json({ success: true, assignedOfficerId: null });
    }

    const val = String(officerId);
    await postModel.findByIdAndUpdate(id, { $set: { assignedOfficerId: val } });
    return res.json({ success: true, assignedOfficerId: val });
  } catch (err) {
    console.error('assign error', err);
    return res.status(500).json({ success: false });
  }
});

// Generate random alphanumeric officer ID
function generateOfficerId(length = 8) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

// Generate prefixed unique-style ID e.g., GOV/NGO/SCI + random alphanumeric
function generatePrefixedId(prefix = 'ID', length = 6) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = String(prefix || 'ID');
  for (let i = 0; i < length; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

// Master-only: create new officer
app.post('/admin/officers', requireLogin, requireRole(['master']), async (req, res) => {
  try {
    const { fullName, email, designation, state, district, department, mobile, password } = req.body;
    if (!password || !fullName) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const existing = await officialModel.findOne({ userEmail: email });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Official account already exists' });
    }

    // generate unique id
    let newId;
    for (let i = 0; i < 5; i++) {
      newId = generateOfficerId(8);
      const clash = await officialModel.findOne({ id: newId });
      if (!clash) break;
      newId = null;
    }
    if (!newId) {
      return res.status(500).json({ success: false, message: 'Failed to generate unique ID' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const doc = new officialModel({
      name: fullName,
      userEmail: email,
      designation: designation || 'officer',
      state,
      district,
      department,
      id: newId,
      phone: mobile ? Number(mobile) : undefined,
      password: hashed
    });
    await doc.save();

    return res.json({ success: true, officer: { id: doc.id, email: doc.userEmail, name: doc.name } });
  } catch (err) {
    console.error('create officer error:', err);
    return res.status(500).json({ success: false });
  }
});

// Update an existing admin (Master only)
app.put('/admin/officers/:id', requireLogin, requireRole(['master']), async (req, res) => {
  try {
    const id = req.params.id;
    const { fullName, email, state, district, department, mobile, password } = req.body;

    const set = {};
    if (typeof fullName === 'string') set.name = fullName;
    if (typeof email === 'string') set.userEmail = email;
    if (typeof state === 'string') set.state = state;
    if (typeof district === 'string') set.district = district;
    if (typeof department === 'string') set.department = department;
    if (typeof mobile !== 'undefined') set.phone = mobile ? Number(mobile) : undefined;

    if (password && String(password).trim()) {
      set.password = await bcrypt.hash(String(password), 10);
    }

    // Prevent duplicate email
    if (set.userEmail) {
      const existing = await officialModel.findOne({ userEmail: set.userEmail, id: { $ne: id } });
      if (existing) {
        return res.status(409).json({ success: false, message: 'Email already in use' });
      }
    }

    const updated = await officialModel.findOneAndUpdate(
      { id, designation: 'admin' },
      { $set: set },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ success: false, message: 'Admin not found' });
    }

    return res.json({
      success: true,
      officer: {
        id: updated.id,
        name: updated.name,
        email: updated.userEmail,
        state: updated.state,
        district: updated.district,
        department: updated.department
      }
    });
  } catch (err) {
    console.error('update admin error:', err);
    return res.status(500).json({ success: false });
  }
});

// Delete an existing admin (Master only)
app.delete('/admin/officers/:id', requireLogin, requireRole(['master']), async (req, res) => {
  try {
    const id = req.params.id;
    const deleted = await officialModel.findOneAndDelete({ id, designation: 'admin' });
    if (!deleted) {
      return res.status(404).json({ success: false, message: 'Admin not found' });
    }
    return res.json({ success: true });
  } catch (err) {
    console.error('delete admin error:', err);
    return res.status(500).json({ success: false });
  }
});

// Communications board (Master and Officials)
app.get('/communications', requireLogin, requireRole(['master', 'official']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const page = Math.max(1, Number(req.query.page || 1));
    const pageSize = 15;
    const filter = {};

    if (req.query.category) filter.category = req.query.category;
    if (req.query.state) filter.state = req.query.state;
    if (req.query.district) filter.district = req.query.district;

    const total = await communicationModel.countDocuments(filter);
    const threads = await communicationModel.find(filter)
      .sort({ updatedAt: -1 })
      .skip((page - 1) * pageSize)
      .limit(pageSize)
      .lean();

    res.render('communications', {
      title: 'Communications',
      language,
      activeTab: 'communications',
      threads,
      page,
      total,
      pageSize
    });
  } catch (err) {
    console.error('communications error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/communications', requireLogin, requireRole(['master', 'official']), async (req, res) => {
  try {
    const { title, body, category, state, district } = req.body;
    if (!title || !body) return res.status(400).json({ success: false, message: 'Missing fields' });

    const doc = new communicationModel({
      title,
      body,
      category: category || 'general',
      state: state || undefined,
      district: district || undefined,
      authorId: String(req.session.user.employeeId || 'MASTER'),
      authorRole: req.session.user.role,
      authorName: req.session.user.role === 'master' ? 'Master' : (req.session.user.email || 'Official')
    });
    await doc.save();
    return res.json({ success: true, id: String(doc._id) });
  } catch (err) {
    console.error('create communication error:', err);
    return res.status(500).json({ success: false });
  }
});

app.post('/communications/:id/comment', requireLogin, requireRole(['master', 'official']), async (req, res) => {
  try {
    const id = req.params.id;
    const { text } = req.body;
    if (!text) return res.status(400).json({ success: false, message: 'Missing text' });

    const comment = {
      text,
      authorId: String(req.session.user.employeeId || 'MASTER'),
      authorRole: req.session.user.role,
      authorName: req.session.user.role === 'master' ? 'Master' : (req.session.user.email || 'Official')
    };

    await communicationModel.findByIdAndUpdate(id, {
      $push: { comments: comment },
      $set: { updatedAt: new Date() }
    });

    return res.json({ success: true });
  } catch (err) {
    console.error('comment error:', err);
    return res.status(500).json({ success: false });
  }
});

// Report data change via email (Master and Officials)
app.post('/communications/data-change-report', requireLogin, requireRole(['master', 'official']), async (req, res) => {
  try {
    const { description, location, date, diseaseName } = req.body;
    if (!description || !location || !date || !diseaseName) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const reporter = req.session.user || {};
    const subject = `Data Change Report - ${diseaseName}`;

    const text = [
      'A data change has been reported by an administrator/officer.',
      '',
      `Disease: ${diseaseName}`,
      `Location: ${location}`,
      `Date: ${date}`,
      '',
      'Description:',
      description,
      '',
      'Reporter Details:',
      `Role: ${reporter.role || 'unknown'}`,
      `Employee ID: ${reporter.employeeId || 'N/A'}`,
      `Email: ${reporter.email || 'N/A'}`
    ].join('\n');

    const html = `
      <div>
        <p>A data change has been reported by an administrator/officer.</p>
        <ul>
          <li><strong>Disease:</strong> ${escapeHtml(diseaseName)}</li>
          <li><strong>Location:</strong> ${escapeHtml(location)}</li>
          <li><strong>Date:</strong> ${escapeHtml(date)}</li>
        </ul>
        <p><strong>Description:</strong></p>
        <p>${escapeHtml(description).replace(/\n/g, '<br/>')}</p>
        <hr/>
        <p><strong>Reporter Details</strong><br/>
          Role: ${escapeHtml(reporter.role || 'unknown')}<br/>
          Employee ID: ${escapeHtml(reporter.employeeId || 'N/A')}<br/>
          Email: ${escapeHtml(reporter.email || 'N/A')}</p>
      </div>`;

    const fromEmail = process.env.SMTP_FROM || process.env.SENDGRID_FROM || process.env.GMAIL_USER || process.env.SMTP_USER;
    const toEmail = process.env.EMAIL_TO || 'saptarshibhunia5@gmail.com';

    // Prefer SendGrid HTTPS API on hosted environments to avoid SMTP timeouts
    const sendgridKey = process.env.SENDGRID_API_KEY || process.env.SENDGRID_API;
    if (sendgridKey && fromEmail) {
      try {
        console.log('Sending email via SendGrid HTTP API');
        await sendViaSendGrid({
          from: fromEmail,
          to: toEmail,
          subject,
          text,
          html,
          apiKey: sendgridKey,
        });
        return res.json({ success: true, provider: 'sendgrid' });
      } catch (e) {
        console.error('SendGrid send error, falling back to SMTP if configured:', e);
      }
    }

    // Configure SMTP transporter from env (supports fallback to Ethereal in dev)
    const host = process.env.SMTP_HOST || null;
    const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : (host ? 587 : undefined);
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;
    const user = process.env.SMTP_USER || process.env.GMAIL_USER || null;
    const pass = process.env.SMTP_PASS || process.env.GMAIL_PASS || null;

    let transporter;
    let usingTestAccount = false;

    if (user && pass) {
      console.log('Sending email via SMTP', { host, port, secure });
      transporter = host
        ? nodemailer.createTransport({
            host,
            port,
            secure,
            auth: { user, pass },
            connectionTimeout: 15000,
            greetingTimeout: 10000,
            socketTimeout: 20000,
            tls: { rejectUnauthorized: false },
          })
        : nodemailer.createTransport({
            service: 'gmail',
            auth: { user, pass },
            connectionTimeout: 15000,
            greetingTimeout: 10000,
            socketTimeout: 20000,
          });
    } else {
      // Dev fallback: auto-create an Ethereal test account to avoid hard failure
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass },
        connectionTimeout: 15000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
      });
      usingTestAccount = true;
      console.warn('Email service not fully configured; using Ethereal test account for preview only.');
    }

    const mailOptions = {
      from: fromEmail || user,
      to: toEmail,
      subject,
      text,
      html,
    };

    const info = await transporter.sendMail(mailOptions);
    const previewUrl = nodemailer.getTestMessageUrl(info) || null;
    if (usingTestAccount && previewUrl) {
      console.log('Ethereal preview URL:', previewUrl);
    }
    return res.json({ success: true, previewUrl, provider: usingTestAccount ? 'ethereal' : 'smtp' });
  } catch (err) {
    console.error('data-change-report error:', err);
    return res.status(500).json({ success: false, message: 'Failed to send email' });
  }
});

// Helper to escape HTML entities
function escapeHtml(str) {
  try {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  } catch (e) {
    return '';
  }
}

// Admin management page (Master only)
app.get('/admin-management', requireLogin, requireRole(['master']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const admins = await officialModel.find({ designation: 'admin' }).lean();
    res.render('admin-management', {
      title: 'Admin Management',
      language,
      activeTab: 'admin-management',
      admins
    });
  } catch (err) {
    console.error('admin-management error:', err);
    res.status(500).send('Internal server error');
  }
});

app.post('/login', async (req, res) => {
  try {
    const type = req.body.type || req.body.role || 'public';

    if (type === 'official') {
      const employeeId = String(req.body.officialEmployeeId || '').trim();
      const password = req.body.password;

      // Hardcoded Master login (bypasses DB)
      if (employeeId === MASTER_ID && password === MASTER_PASSWORD) {
        req.session.user = { role: 'master', email: null, employeeId: MASTER_ID };
        return res.json({ success: true, redirect: '/dashboard' });
      }

      // Normal officer login via DB (by ID only)
      const user = await officialModel.findOne({ id: employeeId });
      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      const ok = await bcrypt.compare(password, user.password || '');
      if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      req.session.user = { role: 'official', email: user.userEmail || null, employeeId: user.id, isAdmin: user.designation === 'admin' };
      return res.json({ success: true, redirect: '/dashboard' });
    } else if (type === 'government') {
      const employeeId = String(req.body.employeeId || req.body.officialEmployeeId || req.body.governmentEmployeeId || '').trim();
      const password = req.body.password;

      if (employeeId) {
        const prefix = employeeId.slice(0,3).toUpperCase();
        if (prefix === 'SCI') {
          const user = await researcherModel.findOne({ id: employeeId });
          if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials (researcher not found)' });
          const ok = await bcrypt.compare(password, user.password || '');
          if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
          req.session.user = { role: 'researcher', email: user.email || null, researcherId: String(user._id), employeeId };
          return res.json({ success: true, redirect: '/r/dashboard' });
        } else if (prefix === 'GOV') {
          const user = await governmentModel.findOne({ id: employeeId });
          if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials (government not found)' });
          const ok = await bcrypt.compare(password, user.password || '');
          if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
          req.session.user = { role: 'government', email: user.email || null, governmentId: String(user._id), employeeId };
          return res.json({ success: true, redirect: '/data-plotting' });
        } else if (prefix === 'NGO') {
          const user = await ngoModel.findOne({ id: employeeId });
          if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials (NGO not found)' });
          const ok = await bcrypt.compare(password, user.password || '');
          if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
          req.session.user = { role: 'ngo', email: user.email || null, ngoId: String(user._id), employeeId };
          return res.json({ success: true, redirect: '/dashboard' });
        } else {
          // Admins and Master Admin
          if (employeeId === MASTER_ID && password === MASTER_PASSWORD) {
            req.session.user = { role: 'master', email: null, employeeId: MASTER_ID };
            return res.json({ success: true, redirect: '/dashboard' });
          }
          const user = await officialModel.findOne({ id: employeeId });
          if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials (admin/officer not found)' });
          const ok = await bcrypt.compare(password, user.password || '');
          if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
          req.session.user = { role: 'official', email: user.userEmail || null, employeeId: user.id, isAdmin: user.designation === 'admin' };
          return res.json({ success: true, redirect: '/dashboard' });
        }
      } else {
        // Fallback: legacy email login for government user (for transition safety)
        const email = String(req.body.email || '').trim();
        const user = await governmentModel.findOne({ email });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        const ok = await bcrypt.compare(password, user.password || '');
        if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        req.session.user = { role: 'government', email: user.email, governmentId: String(user._id) };
        return res.json({ success: true, redirect: '/data-plotting' });
      }
    } else if (type === 'researcher') {
      const email = String(req.body.email || '').trim();
      const password = req.body.password;
      const user = await researcherModel.findOne({ email });
      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.password || '');
      if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
      req.session.user = { role: 'researcher', email: user.email, researcherId: String(user._id) };
      return res.json({ success: true, redirect: '/dashboard' });
    } else if (type === 'ngo') {
      const email = String(req.body.email || '').trim();
      const password = req.body.password;
      const user = await ngoModel.findOne({ email });
      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.password || '');
      if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });
      req.session.user = { role: 'ngo', email: user.email, ngoId: String(user._id) };
      return res.json({ success: true, redirect: '/dashboard' });
    } else {
      const email = req.body.publicEmail;
      const password = req.body.password;

      const user = await generalModel.findOne({ userEmail: email });
      if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.password || '');
      if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

      req.session.user = { role: 'general', email: user.userEmail };
      return res.json({ success: true, redirect: '/dashboard' });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Government Body: Data Plotting page
app.get('/data-plotting', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const totalCases = await dataModel.countDocuments({});

    let riskLevel = 'Low';
    if (totalCases > 200000) riskLevel = 'High';
    else if (totalCases > 50000) riskLevel = 'Medium';

    const totalPolicies = await policyModel.countDocuments({});

    res.render('data-plotting', {
      title: 'Data Plotting',
      language,
      activeTab: 'data-plotting',
      stats: { totalCases, riskLevel, totalPolicies }
    });
  } catch (err) {
    console.error('data-plotting error:', err);
    const language = req.query.lang || 'en';
    res.render('data-plotting', {
      title: 'Data Plotting',
      language,
      activeTab: 'data-plotting',
      stats: { totalCases: 0, riskLevel: 'Low', totalPolicies: 0 }
    });
  }
});

// Government Body: User Management page (NGO + Researcher)
app.get('/user-management', requireLogin, requireRole(['government']), (req, res) => {
  const language = req.query.lang || 'en';
  res.render('user-management', { title: 'User Management', language, activeTab: 'user-management' });
});

// Government Body: Research Posts listing
app.get('/research-posts', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const posts = await researchPostModel.find({}).sort({ createdAt: -1 }).lean();
    res.render('research-posts', { title: 'Research Posts', language, activeTab: 'research-posts', posts });
  } catch (e) {
    console.error('research-posts error', e);
    res.render('research-posts', { title: 'Research Posts', language: req.query.lang || 'en', activeTab: 'research-posts', posts: [] });
  }
});

// Government Body: Policies management (list + create)
app.get('/policies', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const policies = await policyModel.find({}).sort({ createdAt: -1 }).lean();
    res.render('policies', {
      title: 'Policies',
      language,
      activeTab: 'policies',
      policies,
      created: req.query.created === '1',
      error: null
    });
  } catch (e) {
    console.error('policies list error', e);
    res.status(500).render('policies', {
      title: 'Policies',
      language: req.query.lang || 'en',
      activeTab: 'policies',
      policies: [],
      created: false,
      error: 'Failed to load policies.'
    });
  }
});

app.post('/policies', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const { title, description } = req.body || {};
    if (!title || !description) {
      const language = req.query.lang || 'en';
      const policies = await policyModel.find({}).sort({ createdAt: -1 }).lean();
      return res.status(400).render('policies', {
        title: 'Policies',
        language,
        activeTab: 'policies',
        policies,
        created: false,
        error: 'Title and Description are required.'
      });
    }

    const createdBy = (req.session.user && (req.session.user.employeeId || req.session.user.email)) || null;
    const doc = new policyModel({ title: String(title).trim(), description: String(description).trim(), createdBy });
    await doc.save();
    return res.redirect('/policies?created=1');
  } catch (e) {
    console.error('policies create error', e);
    const language = req.query.lang || 'en';
    try {
      const policies = await policyModel.find({}).sort({ createdAt: -1 }).lean();
      return res.status(500).render('policies', {
        title: 'Policies',
        language,
        activeTab: 'policies',
        policies,
        created: false,
        error: 'Failed to create policy.'
      });
    } catch(_) {
      return res.status(500).send('Failed to create policy');
    }
  }
});

// Admin (official with admin designation): NGO Management
app.get('/admin/ngo-management', requireLogin, requireRole(['official']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    if (!req.session.user || !req.session.user.isAdmin) return res.redirect('/dashboard');
    const ngos = await ngoModel.find({}).sort({ createdAt: -1 }).lean();
    const tasks = await ngoTaskModel.find({ assignedBy: req.session.user.employeeId }).sort({ createdAt: -1 }).lean();
    res.render('admin-ngo-management', {
      title: 'NGO Management',
      language,
      activeTab: 'ngo-management',
      ngos,
      tasks,
      created: req.query.created === '1',
      error: null
    });
  } catch (e) {
    console.error('ngo-management page error', e);
    res.render('admin-ngo-management', {
      title: 'NGO Management',
      language: req.query.lang || 'en',
      activeTab: 'ngo-management',
      ngos: [],
      tasks: [],
      created: false,
      error: 'Failed to load data'
    });
  }
});

app.post('/admin/ngo-management/tasks', requireLogin, requireRole(['official']), async (req, res) => {
  try {
    if (!req.session.user || !req.session.user.isAdmin) return res.redirect('/dashboard');
    const { title, description, ngoId } = req.body || {};
    if (!title || !description || !ngoId) {
      const language = req.query.lang || 'en';
      const ngos = await ngoModel.find({}).lean();
      const tasks = await ngoTaskModel.find({ assignedBy: req.session.user.employeeId }).sort({ createdAt: -1 }).lean();
      return res.status(400).render('admin-ngo-management', {
        title: 'NGO Management', language, activeTab: 'ngo-management', ngos, tasks, created: false, error: 'All fields are required.'
      });
    }
    const task = new ngoTaskModel({
      title: String(title).trim(),
      description: String(description).trim(),
      ngoId: String(ngoId).trim(),
      assignedBy: req.session.user.employeeId
    });
    await task.save();
    return res.redirect('/admin/ngo-management?created=1');
  } catch (e) {
    console.error('create NGO task error', e);
    try {
      const language = req.query.lang || 'en';
      const ngos = await ngoModel.find({}).lean();
      const tasks = await ngoTaskModel.find({ assignedBy: req.session.user.employeeId }).sort({ createdAt: -1 }).lean();
      return res.status(500).render('admin-ngo-management', {
        title: 'NGO Management', language, activeTab: 'ngo-management', ngos, tasks, created: false, error: 'Failed to assign task.'
      });
    } catch (_e) {
      return res.status(500).send('Failed to assign task');
    }
  }
});

// NGO: Dashboard (sampling map)
app.get('/ngo/dashboard', requireLogin, requireRole(['ngo']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const totalCases = await dataModel.countDocuments({});

    return res.render('ngodashboard', {
      title: 'NGO Dashboard',
      language,
      activeTab: 'ngo-dashboard',
      stats: { totalCases }
    });
  } catch (e) {
    console.error('ngo dashboard error', e);
    const language = req.query.lang || 'en';
    return res.render('ngodashboard', {
      title: 'NGO Dashboard',
      language,
      activeTab: 'ngo-dashboard',
      stats: { totalCases: 0 }
    });
  }
});

// NGO: View government policies (read-only)
app.get('/ngo/policies', requireLogin, requireRole(['ngo']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const policies = await policyModel.find({}).sort({ createdAt: -1 }).lean();
    res.render('ngo-policies', { title: 'Policies', language, activeTab: 'ngo-policies', policies });
  } catch (e) {
    console.error('ngo policies error', e);
    res.render('ngo-policies', { title: 'Policies', language: req.query.lang || 'en', activeTab: 'ngo-policies', policies: [] });
  }
});

// NGO: View assigned tasks from Admins (non-master)
app.get('/ngo/tasks', requireLogin, requireRole(['ngo']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const meId = String(req.session.user && req.session.user.ngoId || '');
    const me = meId ? await ngoModel.findById(meId).lean() : null;
    const ngoCode = me && me.id ? me.id : null;

    const tasks = ngoCode
      ? await ngoTaskModel.find({ ngoId: ngoCode }).sort({ createdAt: -1 }).lean()
      : [];

    return res.render('ngo-tasks', {
      title: 'Assigned Tasks',
      language,
      activeTab: 'ngo-tasks',
      ngoCode,
      tasks
    });
  } catch (e) {
    console.error('ngo tasks error', e);
    const language = req.query.lang || 'en';
    return res.render('ngo-tasks', {
      title: 'Assigned Tasks',
      language,
      activeTab: 'ngo-tasks',
      ngoCode: null,
      tasks: []
    });
  }
});

// General Public: View government policies (read-only)
app.get('/public/policies', requireLogin, requireRole(['general']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const policies = await policyModel.find({}).sort({ createdAt: -1 }).lean();
    res.render('public-policies', { title: 'Policies', language, activeTab: 'public-policies', policies });
  } catch (e) {
    console.error('public policies error', e);
    res.render('public-policies', { title: 'Policies', language: req.query.lang || 'en', activeTab: 'public-policies', policies: [] });
  }
});

// APIs for NGO management (Government only)
app.get('/api/ngos', requireLogin, requireRole(['government']), async (req, res) => {
  try { const list = await ngoModel.find({}).sort({ createdAt: -1 }).lean(); res.json({ success: true, list }); } catch (e) { res.status(500).json({ success: false }); }
});
app.post('/api/ngos', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const { name, email, registrationNo, focusAreas, state, district, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Missing fields' });
    const exists = await ngoModel.findOne({ email });
    if (exists) return res.status(409).json({ success: false, message: 'Email already exists' });

    // Generate unique NGO ID
    let newId = null;
    for (let i = 0; i < 6; i++) {
      const candidate = generatePrefixedId('NGO', 6);
      const clash = await ngoModel.findOne({ id: candidate });
      if (!clash) { newId = candidate; break; }
    }
    if (!newId) return res.status(500).json({ success: false, message: 'Failed to generate unique NGO ID' });

    const hashed = await bcrypt.hash(String(password), 10);
    const doc = new ngoModel({
      id: newId,
      name,
      email,
      registrationNo,
      focusAreas: Array.isArray(focusAreas) ? focusAreas : String(focusAreas||'').split(',').map(s=>s.trim()).filter(Boolean),
      state,
      district,
      password: hashed
    });
    await doc.save();
    res.json({ success: true, id: String(doc._id), code: doc.id });
  } catch (e) { console.error('ngo create', e); res.status(500).json({ success: false }); }
});
app.put('/api/ngos/:id', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, email, registrationNo, focusAreas, state, district, password } = req.body;
    const set = {};
    if (name!=null) set.name = name;
    if (email!=null) set.email = email;
    if (registrationNo!=null) set.registrationNo = registrationNo;
    if (typeof focusAreas !== 'undefined') set.focusAreas = Array.isArray(focusAreas)? focusAreas : String(focusAreas||'').split(',').map(s=>s.trim()).filter(Boolean);
    if (state!=null) set.state = state;
    if (district!=null) set.district = district;
    if (password && String(password).trim()) set.password = await bcrypt.hash(String(password), 10);
    const updated = await ngoModel.findByIdAndUpdate(id, { $set: set }, { new: true });
    if (!updated) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true });
  } catch (e) { console.error('ngo update', e); res.status(500).json({ success: false }); }
});
app.delete('/api/ngos/:id', requireLogin, requireRole(['government']), async (req, res) => {
  try { const id = req.params.id; const del = await ngoModel.findByIdAndDelete(id); if (!del) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); }
});

// APIs for Researcher management (Government only)
app.get('/api/researchers', requireLogin, requireRole(['government']), async (req, res) => {
  try { const list = await researcherModel.find({}).sort({ createdAt: -1 }).lean(); res.json({ success: true, list }); } catch (e) { res.status(500).json({ success: false }); }
});
app.post('/api/researchers', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const { name, email, affiliation, state, district, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Missing fields' });
    const exists = await researcherModel.findOne({ email });
    if (exists) return res.status(409).json({ success: false, message: 'Email already exists' });

    // Generate unique SCI ID
    let newId = null;
    for (let i = 0; i < 6; i++) {
      const candidate = generatePrefixedId('SCI', 6);
      const clash = await researcherModel.findOne({ id: candidate });
      if (!clash) { newId = candidate; break; }
    }
    if (!newId) return res.status(500).json({ success: false, message: 'Failed to generate unique Researcher ID' });

    const hashed = await bcrypt.hash(String(password), 10);
    const doc = new researcherModel({ id: newId, name, email, affiliation, state, district, password: hashed });
    await doc.save();
    res.json({ success: true, id: String(doc._id), code: doc.id });
  } catch (e) { console.error('researcher create', e); res.status(500).json({ success: false }); }
});
app.put('/api/researchers/:id', requireLogin, requireRole(['government']), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, email, affiliation, state, district, password } = req.body;
    const set = {};
    if (name!=null) set.name = name;
    if (email!=null) set.email = email;
    if (affiliation!=null) set.affiliation = affiliation;
    if (state!=null) set.state = state;
    if (district!=null) set.district = district;
    if (password && String(password).trim()) set.password = await bcrypt.hash(String(password), 10);
    const updated = await researcherModel.findByIdAndUpdate(id, { $set: set }, { new: true });
    if (!updated) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true });
  } catch (e) { console.error('researcher update', e); res.status(500).json({ success: false }); }
});
app.delete('/api/researchers/:id', requireLogin, requireRole(['government']), async (req, res) => {
  try { const id = req.params.id; const del = await researcherModel.findByIdAndDelete(id); if (!del) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); }
});

// Researcher routes
app.get('/r/analysis', requireLogin, requireRole(['researcher']), async (req, res) => {
  const language = req.query.lang || 'en';

  // Initial navigation shows a loader page and then re-requests with ready=1
  if (!req.xhr && req.headers.accept && req.headers.accept.includes('text/html') && !req.query.ready) {
    return res.render('analysis-loader', { layout: false });
  }

  async function fetchAnalysisFromFlask(query) {
    const base = (process.env.FLASK_URL || FLASK_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');
    const url = base + '/api/analyze' + (query ? ('?' + query) : '');

    // Serve from cache if fresh
    const cached = analysisCache.get(query || '_global');
    const now = Date.now();
    if (cached && (now - cached.ts) < ANALYSIS_TTL_MS) {
      return cached.payload;
    }

    const fetchJson = (tries = 2) => new Promise((resolve) => {
      try {
        const lib = url.startsWith('https') ? https : http;
        const options = {
          timeout: 55000,
          headers: {
            'Accept': 'application/json',
            'Connection': 'keep-alive',
            'User-Agent': 'AquaFlow-Node-Client/1.0'
          },
          agent: url.startsWith('https') ? keepAliveHttpsAgent : keepAliveHttpAgent,
        };

        const attempt = (n) => {
          let aborted = false;
          const reqFlask = lib.get(url, options, (resp) => {
            let data = '';
            resp.on('data', (c) => { data += c.toString(); });
            resp.on('end', () => {
              if (aborted) return;
              try {
                const json = JSON.parse(data);
                const payload = (json && typeof json === 'object') ? json : { success: false, data: [], charts: {}, statistics: {}, mapPath: null };
                analysisCache.set(query || '_global', { payload, ts: Date.now() });
                resolve(payload);
              } catch (e) {
                console.error('Flask analysis parse error:', e);
                console.error('Raw response:', data);
                if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
                resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
              }
            });
            resp.on('error', (err) => {
              if (aborted) return;
              console.error('Flask analysis response error:', err);
              if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
              resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
            });
            resp.on('close', () => {
              if (aborted) return;
              if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
              console.error('Flask analysis connection closed without data');
              resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
            });
          });

          reqFlask.on('error', (err) => {
            if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
            console.error('Flask analysis request error:', err);
            resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
          });

          reqFlask.setTimeout(55000, () => {
            aborted = true;
            try { reqFlask.destroy(); } catch (_) {}
            if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
            console.error('Flask analysis request timeout after 55 seconds');
            resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
          });

          reqFlask.end();
        };
        attempt(1);
      } catch (e) {
        console.error('fetchAnalysisFromFlask fatal error:', e);
        resolve({ success: false, data: [], charts: {}, statistics: {}, mapPath: null });
      }
    });

    return await fetchJson(2);
  }

  try {
    // Filter by researcher's state/district if available
    const meId = String(req.session.user && req.session.user.researcherId || '');
    const me = meId ? await researcherModel.findById(meId).lean() : null;
    const qs = [];
    if (me && me.state) qs.push('state=' + encodeURIComponent(me.state));
    if (me && me.district) qs.push('district=' + encodeURIComponent(me.district));

    // Optional: limit results or min_risk filter
    // qs.push('limit=5000');

    let initialQuery = qs.join('&');
    let payload = await fetchAnalysisFromFlask(initialQuery);
    let usedQuery = initialQuery;

    // Fallback: if no data for area filters, fetch global analysis and update usedQuery
    if (!payload || !payload.success || !Array.isArray(payload.data) || payload.data.length === 0) {
      payload = await fetchAnalysisFromFlask('');
      usedQuery = '';
    }

    const hasMap = payload && payload.mapPath;
    const viewFlaskBase = hasMap ? '' : (process.env.FLASK_URL || FLASK_URL || '').replace(/\/+$/, '');
    if (hasMap) {
      // Use local proxy to avoid cross-origin iframe/X-Frame-Options issues
      payload.mapPath = '/proxy/flask-map';
    }

    // Build proxied plot URLs for embedding on same origin (match the query actually used)
    const baseFlask = (process.env.FLASK_URL || FLASK_URL || '').replace(/\/+$/, '');
    const proxiedPlot = '/proxy/flask-plot' + (usedQuery ? ('?' + usedQuery) : '');

    return res.render('researcher-page', {
      title: 'Real-time Analysis',
      language,
      activeTab: 'r-analysis',
      section: 'analysis',
      analysis: payload || {},
      flaskBase: viewFlaskBase,
      plotUrl: proxiedPlot
    });
  } catch (e) {
    console.error('/r/analysis error:', e);
    return res.render('researcher-page', {
      title: 'Real-time Analysis',
      language,
      activeTab: 'r-analysis',
      section: 'analysis',
      analysis: { success: false, data: [], charts: {}, statistics: {}, mapPath: null },
      flaskBase: (process.env.FLASK_URL || FLASK_URL || '').replace(/\/+$/, ''),
      plotUrl: '/proxy/flask-plot'
    });
  }
});

// Proxy the Flask-generated plot image (PNG)
app.get('/proxy/flask-plot', async (req, res) => {
  try {
    const base = (process.env.FLASK_URL || FLASK_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');
    const qs = req.originalUrl.split('?')[1] || '';
    const key = qs || '_default';
    const primaryUrl = base + '/api/plot' + (qs ? ('?' + qs) : '');
    const fallbackUrl = base + '/api/plot';

    const sendPng = (buf, cacheStatus = 'MISS') => {
      res.status(200);
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('X-Cache', cacheStatus);
      res.end(buf);
    };

    const serveStaleIfAny = (statusCode = 502, message = 'Plot unavailable') => {
      const entry = plotCache.get(key) || plotCache.get('_default');
      if (entry && entry.buf) {
        res.setHeader('Warning', '110 - "Response is stale"');
        return sendPng(entry.buf, 'STALE');
      }
      res.status(statusCode).send(message);
    };

    // Serve fresh cache if valid
    const cached = plotCache.get(key);
    const now = Date.now();
    if (cached && (now - cached.ts) < PLOT_TTL_MS) {
      return sendPng(cached.buf, 'HIT');
    }

    // If there's an inflight fetch for this key, await it
    if (inflightPlot.has(key)) {
      try {
        const buf = await inflightPlot.get(key);
        return sendPng(buf, cached ? 'STALE-REFRESH' : 'MISS');
      } catch (_) {
        return serveStaleIfAny();
      }
    }

    const fetchOnce = (url, tries = 2) => new Promise((resolve, reject) => {
      const lib = url.startsWith('https') ? https : http;
      const options = {
        headers: {
          'Accept': 'image/png',
          'Connection': 'keep-alive',
          'User-Agent': 'AquaFlow-Node-Client/1.0'
        },
        timeout: 55000,
        agent: url.startsWith('https') ? keepAliveHttpsAgent : keepAliveHttpAgent,
      };
      let done = false;
      const attempt = (n) => {
        const reqFlask = lib.get(url, options, (resp) => {
          const chunks = [];
          resp.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          resp.on('end', () => {
            if (done) return;
            const buf = Buffer.concat(chunks);
            const ct = String((resp.headers && (resp.headers['content-type'] || resp.headers['Content-Type'])) || '').toLowerCase();
            if (resp.statusCode === 200 && ct.includes('image/png') && buf.length > 0) return resolve(buf);
            if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
            reject(new Error('bad_status_or_type_' + (resp.statusCode || '0') + '_' + ct));
          });
        });
        reqFlask.on('error', (err) => {
          if (done) return;
          if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
          reject(err);
        });
        reqFlask.setTimeout(55000, () => { try { reqFlask.destroy(); } catch(_) {}; if (n < tries) return setTimeout(() => attempt(n + 1), n * 500); reject(new Error('timeout')); });
      };
      attempt(1);
    });

    const inflight = (async () => {
      try {
        let buf;
        try {
          buf = await fetchOnce(primaryUrl, 2);
        } catch (_) {
          buf = await fetchOnce(fallbackUrl, 2);
        }
        // update cache
        plotCache.set(key, { buf, ts: Date.now() });
        return buf;
      } finally {
        inflightPlot.delete(key);
      }
    })();

    inflightPlot.set(key, inflight);

    try {
      const buf = await inflight;
      return sendPng(buf, cached ? 'STALE-REFRESH' : 'MISS');
    } catch (e) {
      console.error('proxy plot unavailable', e && e.message);
      return serveStaleIfAny();
    }
  } catch (e) {
    console.error('proxy plot fatal:', e);
    if (!res.headersSent) {
      res.status(500).send('Plot error');
    }
  }
});

// Proxy the Flask-generated Folium map to this domain to ensure iframe renders
app.get('/proxy/flask-map', async (req, res) => {
  try {
    const base = (process.env.FLASK_URL || FLASK_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');
    const key = '_map';

    const sanitizeAndSendHtml = (html, statusCode, cacheStatus = 'MISS') => {
      let out = html || '';
      try {
        out = out.replace(/<meta[^>]+http-equiv=["']?X-Frame-Options["']?[^>]*>/gi, '');
        out = out.replace(/<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi, '');
      } catch (_) {}
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('X-Cache', cacheStatus);
      try { res.removeHeader('X-Frame-Options'); } catch(e) {}
      try { res.removeHeader('Content-Security-Policy'); } catch(e) {}
      res.status(statusCode || 200).send(out);
    };

    const serveStaleIfAny = () => {
      const entry = mapCache.get(key);
      if (entry && entry.html) {
        res.setHeader('Warning', '110 - "Response is stale"');
        return sanitizeAndSendHtml(entry.html, 200, 'STALE');
      }
      res.status(502).send('Map unavailable');
    };

    const cached = mapCache.get(key);
    const now = Date.now();
    if (cached && (now - cached.ts) < MAP_TTL_MS) {
      return sanitizeAndSendHtml(cached.html, 200, 'HIT');
    }

    if (inflightMap.has(key)) {
      try {
        const html = await inflightMap.get(key);
        return sanitizeAndSendHtml(html, 200, cached ? 'STALE-REFRESH' : 'MISS');
      } catch (_) {
        return serveStaleIfAny();
      }
    }

    const fetchText = (url, accept, tries = 2) => new Promise((resolve, reject) => {
      const lib = url.startsWith('https') ? https : http;
      const options = {
        headers: {
          'Accept': accept,
          'Connection': 'keep-alive',
          'User-Agent': 'AquaFlow-Node-Client/1.0'
        },
        timeout: 45000,
        agent: url.startsWith('https') ? keepAliveHttpsAgent : keepAliveHttpAgent,
      };
      const attempt = (n) => {
        const reqFlask = lib.get(url, options, (resp) => {
          let data = '';
          resp.on('data', (c) => { data += c.toString(); });
          resp.on('end', () => {
            if (resp.statusCode === 200 && data) return resolve(data);
            if (n < tries) return setTimeout(() => attempt(n + 1), n * 500);
            reject(new Error('bad_status_' + resp.statusCode));
          });
        });
        reqFlask.on('error', (err) => { if (n < tries) return setTimeout(() => attempt(n + 1), n * 500); reject(err); });
        reqFlask.setTimeout(45000, () => { try { reqFlask.destroy(); } catch(_) {}; if (n < tries) return setTimeout(() => attempt(n + 1), n * 500); reject(new Error('timeout')); });
      };
      attempt(1);
    });

    const inflight = (async () => {
      try {
        let html = await fetchText(base + '/api/map', 'text/html,application/xhtml+xml', 2);
        if (!html) {
          // trigger analysis and try again
          try { await fetchText(base + '/api/analyze', 'application/json', 1); } catch(_) {}
          html = await fetchText(base + '/api/map', 'text/html,application/xhtml+xml', 2);
        }
        mapCache.set(key, { html, ts: Date.now() });
        return html;
      } finally {
        inflightMap.delete(key);
      }
    })();

    inflightMap.set(key, inflight);

    try {
      const html = await inflight;
      return sanitizeAndSendHtml(html, 200, cached ? 'STALE-REFRESH' : 'MISS');
    } catch (e) {
      console.error('proxy map unavailable after analyze', e && e.message);
      return serveStaleIfAny();
    }
  } catch (e) {
    console.error('proxy map fatal:', e);
    res.status(500).send('Map error');
  }
});

// Optional: JSON debug endpoint for analysis payload
app.get('/r/analysis.json', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const meId = String(req.session.user && req.session.user.researcherId || '');
    const me = meId ? await researcherModel.findById(meId).lean() : null;
    const qs = [];
    if (me && me.state) qs.push('state=' + encodeURIComponent(me.state));
    if (me && me.district) qs.push('district=' + encodeURIComponent(me.district));

    async function fetchAnalysisFromFlask(query) {
      const base = (process.env.FLASK_URL || FLASK_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');
      const url = base + '/api/analyze' + (query ? ('?' + query) : '');
      return await new Promise((resolve) => {
        const lib2 = url.startsWith('https') ? https : http;
        const req2 = lib2.get(url, { headers: { 'Accept': 'application/json' }, timeout: 20000 }, (resp) => {
          let buf = '';
          resp.on('data', (c) => buf += c.toString());
          resp.on('end', () => { try { resolve(JSON.parse(buf)); } catch(e){ resolve({ success:false, raw: buf }); } });
        });
        req2.on('error', () => resolve({ success:false }));
        req2.setTimeout(20000, () => { try{ req2.destroy(); }catch(_){}; resolve({ success:false }); });
      });
    }

    const payload = await fetchAnalysisFromFlask(qs.join('&'));
    res.json(payload);
  } catch (e) {
    res.status(500).json({ success:false, error:'debug_failed' });
  }
});

app.get('/r/posts', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const posts = await researchPostModel.find({}).sort({ createdAt: -1 }).lean();
    res.render('researcher-page', { title: 'Research Posts', language, activeTab: 'r-posts', section: 'posts', posts });
  } catch(e) {
    res.status(500).send('Failed to load posts');
  }
});

app.post('/r/posts', requireLogin, requireRole(['researcher']), uploadPdf.single('pdf'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).send('PDF file required');
    const pdfUrl = '/uploads/research/' + file.filename;
    const title = (req.body && req.body.title) ? String(req.body.title) : 'Untitled';
    const authorId = String(req.session.user.researcherId || '');

    const doc = new researchPostModel({
      title,
      content: pdfUrl,
      authorId,
      authorEmail: req.session.user.email || null,
      authorName: 'Researcher'
    });
    await doc.save();
    res.redirect('/r/posts');
  } catch (e) {
    console.error('post upload error', e);
    res.status(500).send('Failed to create post');
  }
});

// Researcher communications (reddit-like threads)
app.get('/r/communications', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const threads = await communicationModel.find({ authorRole: 'researcher' }).sort({ updatedAt: -1 }).lean();
    const safeThreads = (threads||[]).map(t => ({
      _id: t._id,
      title: escapeHtml(t.title||''),
      body: escapeHtml(t.body||''),
      authorId: escapeHtml(t.authorId || ''),
      state: escapeHtml(t.state || ''),
      district: escapeHtml(t.district || ''),
      authorName: escapeHtml(t.authorName || t.authorRole || 'researcher'),
      comments: (t.comments||[]).map(c => ({ authorName: c.authorName || c.authorRole || 'user', text: escapeHtml(c.text||'') }))
    }));
    res.render('researcher-page', { title: 'Communications', language, activeTab: 'r-comms', section: 'comms', threads: safeThreads });
  } catch (e) {
    console.error('researcher comm load', e);
    res.status(500).send('Failed to load communications');
  }
});

app.post('/r/communications', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const { title, body } = req.body || {};
    if (!title || !body) return res.status(400).send('Missing title/body');
    const meId = String(req.session.user.researcherId || '');
    const me = await researcherModel.findById(meId).lean();
    const doc = new communicationModel({
      title,
      body,
      category: 'research',
      state: me && me.state ? me.state : undefined,
      district: me && me.district ? me.district : undefined,
      authorId: meId,
      authorRole: 'researcher',
      authorName: (req.session.user.email || 'Researcher')
    });
    await doc.save();
    res.redirect('/r/communications');
  } catch (e) {
    console.error('researcher thread create', e);
    res.status(500).send('Failed to create thread');
  }
});

app.post('/r/communications/:id/comment', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const id = req.params.id;
    const { text } = req.body || {};
    if (!text) return res.status(400).send('Missing text');
    const comment = {
      text,
      authorId: String(req.session.user.researcherId || ''),
      authorRole: 'researcher',
      authorName: (req.session.user.email || 'Researcher')
    };
    await communicationModel.findByIdAndUpdate(id, { $push: { comments: comment }, $set: { updatedAt: new Date() } });
    res.redirect('/r/communications');
  } catch (e) {
    console.error('researcher comment', e);
    res.status(500).send('Failed to add comment');
  }
});

app.get('/r/dashboard', requireLogin, requireRole(['researcher']), async (req, res) => {
  try {
    const language = req.query.lang || 'en';
    const meId = String(req.session.user.researcherId || '');
    const me = await researcherModel.findById(meId).lean();
    const myTotal = await researchPostModel.countDocuments({ authorId: meId });
    let areaList = [];
    if (me && me.state && me.district) {
      const peers = await researcherModel.find({ state: me.state, district: me.district }, { _id: 1 }).lean();
      const peerIds = peers.map(p => String(p._id));
      areaList = await researchPostModel.find({ authorId: { $in: peerIds } }).sort({ createdAt: -1 }).limit(20).lean();
    }
    res.render('researcher-page', {
      title: 'Researcher Dashboard',
      language,
      activeTab: 'r-dashboard',
      section: 'dashboard',
      myTotal,
      area: { state: (me && me.state) || null, district: (me && me.district) || null },
      areaPosts: areaList
    });
  } catch (e) {
    console.error('researcher dashboard', e);
    res.status(500).send('Failed to load dashboard');
  }
});

app.post('/log-location', (req, res) => {
  const { latitude, longitude } = req.body;
  console.log("User location received:");
  console.log("Latitude:", latitude);
  console.log("Longitude:", longitude);

  res.json({ success: true, message: "Location logged in backend console" });
});


app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/publicDashboard', requireLogin, (req, res) => {
  const language = req.query.lang || 'en';
  res.render('publicDashboard', {
    title: 'Public Dashboard',
    language,
    activeTab: 'dashboard'
  });
})

// Global error handlers
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`http://localhost:3000`)
  console.log(`Smart Health Surveillance System running on http://${HOST}:${PORT}`);
});