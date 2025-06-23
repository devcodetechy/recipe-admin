const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/Recipe_db');

const Recipedb = mongoose.connection;

Recipedb.on('error', console.error.bind(console, 'MongoDB connection error:'));
Recipedb.once('open', () => {
  console.log('Connected to MongoDB');
});

module.exports = Recipedb;