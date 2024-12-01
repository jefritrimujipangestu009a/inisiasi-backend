let jwt = require("jsonwebtoken");
let bcrypt = require("bcrypt");
let userRepository = require("./auth.repository");

function generateToken(user) {
  return jwt.sign({ userId: user.id, username: user.username, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
}

async function register(username, email, password) {
  try {
    let hashedPassword = await bcrypt.hash(password, 10);
    let user = {
      username,
      email,
      password: hashedPassword,
      role: "USER",
    };
    let newUser = await userRepository.createUser(user);
    return newUser;
  } catch (error) {
    throw new Error("Failed to register user");
  }
}

async function login(username, password) {
  let user = await userRepository.findUserByUsername(username);
  if (!user) {
    throw new Error("Invalid username or password");
  }

  let isValidPassword = await bcrypt.compare(password, user.password);

  if (!isValidPassword) {
    throw new Error("Invalid username or password");
  }
  let token = generateToken(user);
  return { user, token };
}

module.exports = { register, login };
