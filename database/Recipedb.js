const mongoose = require('mongoose');
require('dotenv').config(); // ✅ Load .env variables

// ✅ Use the MONGO_URI from .env instead of localhost
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const Recipedb = mongoose.connection;

Recipedb.on('error', console.error.bind(console, 'MongoDB connection error:'));
Recipedb.once('open', () => {
  console.log('✅ Connected to MongoDB Atlas');
});

module.exports = Recipedb;
