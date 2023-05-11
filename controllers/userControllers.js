const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const saltRounds = 10;
const JWT_SECRET = "newtonSchool";

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the email exists in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        message: "User with this E-mail does not exist !!",
        status: "fail",
      });
    }

    // Compare the password with the hashed password stored in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(403).json({
        message: "Invalid Password, try again !!",
        status: "fail",
      });
    }

    // Generate JSON web token (JWT)
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.status(200).json({
      status: "success",
      token,
    });
  } catch (error) {
    console.error(error);
    return res.status(404).json({
      message: "Something went wrong",
      status: "fail",
    });
  }
};

const signupUser = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    // Check if any user with the given email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        message: "User with given Email already registered",
        status: "fail",
      });
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role,
    });

    // Save the user to the database
    await newUser.save();

    return res.status(200).json({
      message: "User SignedUp successfully",
      status: "success",
    });
  } catch (error) {
    console.error(error);
    return res.status(404).json({
      message: "Something went wrong",
      status: "fail",
    });
  }
};

module.exports = { loginUser, signupUser };
