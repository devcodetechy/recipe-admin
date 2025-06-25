// Required modules
var express = require('express');
var router = express.Router();
const User = require('../models/users');
const bcrypt = require('bcryptjs');
const Recipes = require('../models/recipes');
const Admin = require('../models/admin');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

// Cloudinary config
const multer = require('multer');
const { cloudinary, storage } = require('../cloudinaryConfig');
const multerStorage = require('multer-storage-cloudinary');
const upload = require('multer')({ storage });

// Middleware to check admin
function ensureAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/AdminLogin');
}

// Verify JWT Token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Admin creation route
router.get('/createAdmin', async (req, res) => {
  const email = 'vishnusivan2002@gmail.com';
  const password = 'Vishnu@2002';

  const existingUser = await Admin.findOne({ email });
  if (existingUser) return res.send('Email already taken');

  const hashedPassword = await bcrypt.hash(password, 10);
  const newAdmin = new Admin({ email, password: hashedPassword });
  await newAdmin.save();
  res.send('Admin created');
});

// Admin login route
router.post('/AdminLogin', async (req, res) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });

  if (!admin) return res.render('Login', { title: 'Login', message: 'Incorrect Email Address.', errors: [] });
  const isPasswordValid = await bcrypt.compare(password, admin.password);

  if (!isPasswordValid) return res.render('Login', { title: 'Login', message: 'Incorrect password.', errors: [] });

  req.session.adminId = admin._id;
  req.session.isAdmin = true;
  res.redirect('/Recipe-view');
});

// Admin-protected routes (Recipes, Users, Reports)
router.get('/Recipe-view', ensureAdmin, async (req, res) => {
  const search = req.query.search?.trim() || '';
  let recipes = await Recipes.find().populate('Createdby', 'name');

  if (search) {
    const regex = new RegExp(search, 'i');
    recipes = recipes.filter(recipe => regex.test(recipe.title) || regex.test(recipe.Createdby?.name));
  }

  res.render('Recipelist', { title: 'Recipes List', Users: recipes, search });
});

router.get('/Users-List', ensureAdmin, async (req, res) => {
  const users = await User.find();
  res.render('Userlist', { title: 'Users List', users });
});

router.get('/Report-page', ensureAdmin, async (req, res) => {
  const recipes = await Recipes.find().populate('Createdby', 'name').sort({ views: -1 });
  res.render('Reportpage', { title: 'Report Page', Users: recipes });
});

// API: Signup
router.post('/signupapi', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) return res.status(400).json({ message: 'Password and Confirm Password not matching' });

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ message: 'Email already taken' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();
  res.status(201).json({ message: 'Account created successfully' });
});

// API: Login
router.post('/userlogin', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || user.isBlocked) return res.status(401).json({ message: 'User is blocked or does not exist' });

  const isMatch = await bcrypt.compare(req.body.password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ token });
});

// API: Add New Recipe (Cloudinary)
router.post('/addnewrecipes', verifyToken, upload.single('image'), async (req, res) => {
  const userId = req.user.id;
  const { title, ingredients, steps, cookingtime, difficultylevel } = req.body;

  if (!title || !ingredients || !steps || !cookingtime || !difficultylevel)
    return res.status(400).json({ message: 'All fields except image are required' });

  try {
    const imagePath = req.file ? req.file.path : '';
    const newRecipe = new Recipes({
      title,
      ingredients,
      steps,
      cookingtime: parseInt(cookingtime),
      difficultylevel,
      image: imagePath,
      Createdby: userId
    });

    await newRecipe.save();
    res.status(201).json({ message: 'Recipe added successfully', data: newRecipe });
  } catch (error) {
    console.error('Error adding recipe:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// API: Recipe listing
router.get('/recipes', verifyToken, async (req, res) => {
  const recipes = await Recipes.find().populate('Createdby', 'name');
  const data = recipes.map(r => ({
    id: r._id,
    title: r.title,
    ingredients: r.ingredients,
    steps: r.steps,
    cookingtime: r.cookingtime,
    difficultylevel: r.difficultylevel,
    image: r.image,
    Createdby: r.Createdby?.name
  }));
  res.status(200).json({ data });
});

// (Other API routes like /recipesearch, /myrecipes, /passwordreset etc. should be updated similarly)

module.exports = router;
