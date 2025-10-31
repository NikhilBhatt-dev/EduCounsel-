
// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const PDFDocument = require('pdfkit');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "http://localhost:3000", "https://student-counseling-app.vercel.app", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    // Ensure directory exists
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Create unique filename with timestamp
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow only specific file types
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only PDF, JPG, JPEG, and PNG files are allowed'));
    }
  }
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/student_counseling', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Student Details Schema
const studentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  personalInfo: {
    dateOfBirth: Date,
    gender: String,
    category: String,
    address: String,
    parentName: String,
    parentPhone: String
  },
  highSchoolMarks: {
    math: Number,
    science: Number,
    english: Number,
    hindi: Number,
    socialScience: Number,
    total: Number,
    percentage: Number
  },
  plus2Marks: {
    physics: Number,
    chemistry: Number,
    mathematics: Number,
    total: Number,
    percentage: Number
  },
  branchPreferences: [String],
  allocatedBranch: String,
  seatAccepted: { type: Boolean, default: false },
  paymentStatus: { type: String, enum: ['pending', 'submitted', 'verified'], default: 'pending' },
  paymentReceipt: String,
  offerLetter: String,
  rank: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Student = mongoose.models.Student || mongoose.model('Student', studentSchema);


// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Routes

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// User registration
app.post('/api/register', [
  body('name').notEmpty().trim(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('phone').isMobilePhone()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, phone, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      phone,
      role: role || 'student'
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User login
app.post('/api/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Submit student details
app.post('/api/student/details', authenticateToken, async (req, res) => {
  try {
    const { personalInfo, highSchoolMarks, plus2Marks, branchPreferences } = req.body;

    // Calculate totals and percentages
    const hsTotal = Object.values(highSchoolMarks).reduce((sum, mark) => sum + (parseFloat(mark) || 0), 0);
    const plus2Total = plus2Marks.physics + plus2Marks.chemistry + plus2Marks.mathematics;

    const studentData = {
      userId: req.user.userId,
      personalInfo,
      highSchoolMarks: {
        ...highSchoolMarks,
        total: hsTotal,
        percentage: (hsTotal / 500) * 100
      },
      plus2Marks: {
        ...plus2Marks,
        total: plus2Total,
        percentage: (plus2Total / 300) * 100
      },
      branchPreferences
    };

    const existingStudent = await Student.findOne({ userId: req.user.userId });
    let student;

    if (existingStudent) {
      student = await Student.findOneAndUpdate(
        { userId: req.user.userId },
        studentData,
        { new: true }
      );
    } else {
      student = new Student(studentData);
      await student.save();
    }

    // Calculate rank
    await calculateRanks();

    res.json({ message: 'Student details saved successfully', student });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get student details
app.get('/api/student/details', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findOne({ userId: req.user.userId }).populate('userId', 'name email');
    
    if (!student) {
      // Return empty student structure if no data exists yet
      return res.json({
        userId: req.user.userId,
        personalInfo: {},
        highSchoolMarks: {},
        plus2Marks: {},
        branchPreferences: [],
        allocatedBranch: null,
        seatAccepted: false,
        paymentStatus: 'pending',
        paymentReceipt: null,
        offerLetter: null,
        rank: null
      });
    }
    
    res.json(student);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin: Get all students with ranks
app.get('/api/admin/students', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const students = await Student.find()
      .populate('userId', 'name email phone')
      .sort({ rank: 1 });
    
    res.json(students);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin: Allocate seat
app.post('/api/admin/allocate-seat', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { studentId, branch } = req.body;

    const student = await Student.findByIdAndUpdate(
      studentId,
      { allocatedBranch: branch },
      { new: true }
    ).populate('userId', 'name email');

    res.json({ message: 'Seat allocated successfully', student });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Student: Accept seat
app.post('/api/student/accept-seat', authenticateToken, async (req, res) => {
  try {
    const student = await Student.findOneAndUpdate(
      { userId: req.user.userId },
      { seatAccepted: true },
      { new: true }
    );

    res.json({ message: 'Seat accepted successfully', student });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Upload payment receipt
app.post('/api/student/payment-receipt', authenticateToken, upload.single('receipt'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const student = await Student.findOneAndUpdate(
      { userId: req.user.userId },
      { 
        paymentReceipt: req.file.filename,
        paymentStatus: 'submitted'
      },
      { new: true }
    );

    res.json({ message: 'Payment receipt uploaded successfully', student });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Admin: Verify payment
app.post('/api/admin/verify-payment', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { studentId, status } = req.body;

    const student = await Student.findByIdAndUpdate(
      studentId,
      { paymentStatus: status },
      { new: true }
    ).populate('userId', 'name email');

    if (status === 'verified') {
      // Generate offer letter
      await generateOfferLetter(student);
    }

    res.json({ message: 'Payment status updated successfully', student });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Debug route to list uploaded files (remove in production)
app.get('/api/debug/uploads', authenticateToken, requireAdmin, (req, res) => {
  try {
    const uploadsPath = path.join(__dirname, 'uploads');
    const files = fs.readdirSync(uploadsPath);
    res.json({ files, path: uploadsPath });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper functions
async function calculateRanks() {
  const students = await Student.find().sort({ 'plus2Marks.total': -1 });
  
  for (let i = 0; i < students.length; i++) {
    students[i].rank = i + 1;
    await students[i].save();
  }
}

async function generateOfferLetter(student) {
  const doc = new PDFDocument();
  const filename = `offer_letter_${student._id}_${Date.now()}.pdf`;
  const filepath = path.join(__dirname, 'uploads', filename);

  doc.pipe(fs.createWriteStream(filepath));

  // Header
  doc.fontSize(20).text('OFFER LETTER', 50, 50);
  doc.fontSize(12).text('Student Counseling System', 50, 80);
  
  // Student Details
  doc.text(`Date: ${new Date().toLocaleDateString()}`, 50, 120);
  doc.text(`Dear ${student.userId.name},`, 50, 150);
  
  doc.text('We are pleased to inform you that you have been selected for admission to our institution.', 50, 180);
  doc.text(`Allocated Branch: ${student.allocatedBranch}`, 50, 210);
  doc.text(`Rank: ${student.rank}`, 50, 240);
  doc.text(`Total Marks (10+2): ${student.plus2Marks.total}/300`, 50, 270);
  
  doc.text('Please report to the admission office with all required documents.', 50, 320);
  doc.text('Congratulations on your admission!', 50, 350);
  
  doc.text('Best Regards,', 50, 400);
  doc.text('Admission Committee', 50, 420);

  doc.end();

  // Wait for PDF to be written
  return new Promise((resolve, reject) => {
    doc.on('end', () => {
      // Update student record
      Student.findByIdAndUpdate(student._id, { offerLetter: filename })
        .then(() => resolve(filename))
        .catch(reject);
    });
    doc.on('error', reject);
  });
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Create subdirectories
const receiptDir = path.join(uploadsDir, 'receipts');
const offerDir = path.join(uploadsDir, 'offers');

if (!fs.existsSync(receiptDir)) {
  fs.mkdirSync(receiptDir, { recursive: true });
}

if (!fs.existsSync(offerDir)) {
  fs.mkdirSync(offerDir, { recursive: true });
}

// Create public directory structure
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir);
}

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

// Export the Express app for Vercel
module.exports = app;
