const mongoose = require('mongoose');

const RecipeSchema = new mongoose.Schema({
  title: String,
  ingredients: String,
  steps: String,
  cookingtime: Number, // store in minutes instead of Date
  difficultylevel: {
    type: String,
    enum: ['Easy', 'Medium', 'Difficult'],
  },
  image: String,
  Createdby: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  views: {
    type: Number,
    default: 0
  }

});

const Recipe = mongoose.model('Recipe', RecipeSchema);

module.exports = Recipe;
