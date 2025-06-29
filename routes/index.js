var express = require('express');
var router = express.Router();
const User = require('../models/users');
const bcrypt = require('bcryptjs');
const Recipes = require('../models/recipes');
const Admin = require('../models/admin');

const multer = require('multer');
const path = require('path');

const parser = require('../conf/cloudinaryConfig');

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/images'); // Save in public/images folder
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});

// Create multer instance
const upload = multer({ storage });




router.get('/createAdmin', (req, res) => {

    const email = 'vishnusivan2002@gmail.com'
    const password = 'Vishnu@2002'
 
  Admin.findOne({email})
  .then(existingUser => {
    if (existingUser) {
       res.send('Email already taken');
       return 
    }

    return bcrypt.hash(password, 10);

  })
  .then(hashedPassword => {
    if (!hashedPassword) return;

    const newAdmin = new Admin({
      email,
      password: hashedPassword,
    });

    return newAdmin.save();
  })
});



/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: ' MashupStack' });
});

router.get('/AdminLogin', function(req, res, next){
  res.render('Login', { title: 'Login' })
});



function ensureAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.redirect('/AdminLogin');
}




router.post('/AdminLogin', function(req, res, _next){
  const { email, password } = req.body;
  console.log(email,password)

    Admin.findOne({ email })
      .then(admin => {
        
        if (!admin) {
          return res.render('Login', { title:'Login' , message: 'Incorrect Email Address.',errors: [] });
        }
        
        console.log(password)
        console.log(admin.password)
        return bcrypt.compare(password, admin.password);
      })
      .then(isPasswordValid => {
        if (!isPasswordValid) {
          console.log("not valid")
          return res.render('Login', { title:'Login', message: 'Incorrect password.',errors: [] });
        }
        
        req.session.adminId = Admin._id;
        req.session.isAdmin = true;
        res.redirect('/Recipe-view');
      })
      .catch(error => {
        console.error(error.message);
        res.status(500).send('Internal Server Error');
      });
});



router.get('/Recipe-view', ensureAdmin, async (req, res) => {
  const search = req.query.search?.trim() || '';

  try {
    let recipes = await Recipes.find().populate('Createdby', 'name');

    // If there's a search query, filter by title or creator name
    if (search) {
      const regex = new RegExp(search, 'i'); // Case-insensitive

      recipes = recipes.filter(recipe => 
        regex.test(recipe.title) || 
        (recipe.Createdby && regex.test(recipe.Createdby.name))
      );
    }

    res.render('Recipelist', {
      title: 'Recipes List',
      Users: recipes,
      search
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});





// Route: /Users-List
router.get('/Users-List',ensureAdmin, async (req, res) => {
  try {
    const users = await User.find(); 
    res.render('Userlist', { title: 'Users List', users });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});



router.get('/Recipe-details/:id',ensureAdmin, async (req, res) => {
  const recipeId = req.params.id;

  try {
    const recipe = await Recipes.findById(recipeId).populate('Createdby', 'name');

    
    if (!recipe) {
      return res.status(404).send('Recipe not found');
    }

    res.render('Recipedetail', { 
      title: 'Recipe Details', 
      recipe 
    });

  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});



router.get('/user_recipe/:id',ensureAdmin, async (req, res) => {
  const userId = req.params.id;
  console.log("id:",userId)

  try {
    const recipes = await Recipes.find({ Createdby: userId }).populate('Createdby', 'name');

    console.log("user:",recipes)
    
    if (!recipes) {
      return res.status(404).send('Recipe not found');
    }

    console.log("id:",userId)
    res.render('Userrecipes', { 
      title: 'Recipe Details', 
      recipes 
    });

  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});



router.post('/block-user/:id',ensureAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const user = await User.findById(userId);
    const newStatus = !user.isBlocked;

    await User.findByIdAndUpdate(userId, { isBlocked: newStatus });
    
    res.redirect('/Users-List');
  } catch (error) {
    console.error('Error blocking/unblocking user:', error);
    res.status(500).send('Internal Server Error');
  }
});


router.get('/Report-page', ensureAdmin, async (req, res) => {
  try {
    const recipes = await Recipes.find()
      .populate('Createdby', 'name')
      .sort({ views: -1 }); // Sort by views descending

    res.render('Reportpage', {
      title: 'Report Page',
      Users: recipes
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});




router.get('/Logout',ensureAdmin, function (req, res) {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Logout failed');
    }
    res.redirect('/AdminLogin');
  });
});






// User APIs


// Signup API
router.post('/signupapi', (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Password and Confirm Password not matching' });
  }

  const user = new User({name, email, password });
  const validationError = user.validateSync();

  if (validationError) {
    return res.status(400).json({ error: validationError.errors });
  }

  User.findOne({ email })
    .then(existingUser => {
      if (existingUser) {
         res.status(400).json({ message: 'Email already taken' });
         return
      }
      return bcrypt.hash(password, 10);
    })
    .then(hashedPassword => {
      if (!hashedPassword) return;

      const newUser = new User({ email, password: hashedPassword ,name});
      return newUser.save();
    })
    .then(savedUser  => {
      if (!savedUser) return; 
      res.status(201).json({ message: 'Account created successfully' });
    })
    .catch(error => {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
    });
});



const jwt = require('jsonwebtoken');
const { token } = require('morgan');
const { render } = require('../app');
require('dotenv').config(); // Add this at the top if not already
const JWT_SECRET = process.env.JWT_SECRET;




// Login API (fixed)
router.post('/userlogin', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user || user.isBlocked) {
      return res.status(401).json({ message: 'User is blocked or does not exist' });
    }

    const isMatch =await bcrypt.compare(req.body.password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});





const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  const token = authHeader && authHeader.split(' ')[1];
  console.log(token)
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET); 
    req.user = { id: decoded.id }; 
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};



// Recipes API
router.get('/recipes',verifyToken, (req, res) => {
  Recipes.find()
      .populate('Createdby', 'name')
      .then(data => {
          const serializedData = data.map(recipes => ({
              id: recipes._id,
              title: recipes.title,
              ingredients: recipes.ingredients,
              steps: recipes.steps,
              cookingtime: recipes.cookingtime,
              difficultylevel: recipes.difficultylevel,
              image: recipes.image,
              Createdby: recipes.Createdby?.name
          }));
          res.status(200).json({ data: serializedData });
      })
      .catch(error => {
          console.error(error);
          res.status(500).json({ message: 'Internal Server Error' });
      });
});


// Recipes Search API
router.get('/recipesearch',verifyToken, (req, res) => {

  const searchQuery = req.query.search || "";

  Recipes.find({ title: { $regex: searchQuery, $options: 'i' } })
      .populate('Createdby', 'name')
      .then(data => {
          const serializedData = data.map(recipes => ({
              id: recipes._id,
              title: recipes.title,
              ingredients: recipes.ingredients,
              steps: recipes.steps,
              cookingtime: recipes.cookingtime,
              difficultylevel: recipes.difficultylevel,
              image: recipes.image,
              Createdby: recipes.Createdby?.name
          }));
          res.status(200).json({ data: serializedData });
      })
      .catch(error => {
          console.error(error);
          res.status(500).json({ message: 'Internal Server Error' });
      });
});


// Recipesabout API
router.get('/recipes/:id', verifyToken, async (req, res) => {
  const id = req.params.id;

  try {
    // Increment views and get the updated recipe
    const recipe = await Recipes.findByIdAndUpdate(
      id,
      { $inc: { views: 1 } },
      { new: true }
    ).populate('Createdby', 'name');

    if (!recipe) {
      return res.status(404).json({ message: 'Recipe not found' });
    }

    const serializedData = {
      id: recipe._id,
      title: recipe.title, 
      ingredients: recipe.ingredients,
      steps: recipe.steps,
      cookingtime: recipe.cookingtime,
      difficultylevel: recipe.difficultylevel,
      image: recipe.image,
      Createdby: recipe.Createdby?.name,
    };

    res.status(200).json({ data: serializedData });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});




// Myrecipes API
router.get('/myrecipes', verifyToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const recipes = await Recipes.find({ Createdby: userId }).populate('Createdby', 'name');

    if (!recipes || recipes.length === 0) {
      return res.status(404).json({ message: 'No recipes found for this user' });
    }

    const serializedData = recipes.map(recipe => ({
      id: recipe._id,
      title: recipe.title, 
      ingredients: recipe.ingredients,
      steps: recipe.steps,
      cookingtime: recipe.cookingtime,
      difficultylevel: recipe.difficultylevel,
      image: recipe.image,
      Createdby: recipe.Createdby?.name || 'Unknown',
    }));

    res.status(200).json({ data: serializedData });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});





// Myrecipes delete API
router.delete('/myrecipes/:id', verifyToken, (req, res) => {
  const id = req.params.id;

  Recipes.findByIdAndDelete(id)
    .then(deletedRecipe => {
      if (!deletedRecipe) {
        return res.status(404).json({ message: 'Recipe not found' });
      }
      res.status(200).json({ message: 'Recipe deleted successfully'});
    })
    .catch(error => {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
    });
});



// Myrecipesedit update API
router.put('/myrecipesedit/:id', verifyToken, async (req, res) => {
  const recipeId = req.params.id;
  const userId = req.user.id;
  const updatedData = req.body;

  try {
    const recipe = await Recipes.findOneAndUpdate(
      { _id: recipeId, Createdby: userId }, 
      {
        $set: {
          title: updatedData.title,
          ingredients: updatedData.ingredients,
          steps: updatedData.steps,
          cookingtime: updatedData.cookingtime,
          difficultylevel: updatedData.difficultylevel,
          image: updatedData.image
        }
      },
      { new: true } 
    );

    if (!recipe) {
      return res.status(404).json({ message: 'Recipe not found or access denied' });
    }

    res.status(200).json({ message: 'Recipe updated successfully', data: recipe });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});



// Passwordreset API
router.post('/passwordreset', verifyToken, async (req, res) => {
  const userId = req.user.id; 
  const { CurrentPassword, NewPassword, ConfirmPassword } = req.body;
  console.log('token is',token)

  if (!CurrentPassword || !NewPassword || !ConfirmPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (NewPassword !== ConfirmPassword) {
    return res.status(400).json({ message: 'New Password and Confirm Password do not match' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = bcrypt.compare(CurrentPassword, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Current password is incorrect' });

    const hashedPassword = await bcrypt.hash(NewPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});



// Addnewrecipe API
router.post('/addnewrecipes', verifyToken, parser.single('image'), async (req, res) => {
  const userId = req.user.id;
  const { title, ingredients, steps, cookingtime, difficultylevel } = req.body;

  if (!title || !ingredients || !steps || !cookingtime || !difficultylevel) {
    return res.status(400).json({ message: 'All fields except image are required' });
  }

  try {
    const imagePath = req.file.path; 
    console.log(req.file)
    const newRecipe = new Recipes({
      title,
      ingredients,
      steps,
      cookingtime: parseInt(cookingtime), // ensure it's stored as a number
      difficultylevel,
      image: imagePath,
      Createdby: userId
    });

    await newRecipe.save();

    res.status(201).json({ message: 'Recipe added successfully', data: newRecipe });
  } catch (error) {
  console.error('Failed to add recipe:', error.response?.data || error.message || error);
}

});

module.exports = router;

