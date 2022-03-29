const express = require("express");
const app = express();
const pool = require("./db");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { createTokens, validateToken } = require("./JWT");

app.use(express.json());
app.use(cookieParser());


const PORT = process.env.PORT || 3000

//register endpoint
app.post("/users/register", async (req, res) => {

  const { username, email, password, profile_picture } = req.body

  try {

    const hashedPassword = await bcrypt.hash(password, 10);

    var num = '1234567890'
    var OTP = ''
    for (let i = 0; i < 5; i++) {
      OTP += num[Math.floor(Math.random() * 10)]
    }


    const newUser = await pool.query('INSERT INTO users (username, email, password, otp, profile_picture) VALUES ($1, $2, $3, $4, $5) RETURNING *', [username, email, hashedPassword, OTP, profile_picture]);
    res.json({ message: "User has been registered" })
    //res.json(newUser.rows);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }

});




//login endpoint
app.post("/users/login", async (req, res) => {

  const { email, password } = req.body;

  try {

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) return res.status(401).json({ error: "Email is incorrect!" });
    const dbPassword = user.rows[0].password
    bcrypt.compare(password, dbPassword).then((match) => {
      if (!match) {
        res
          .status(400)
          .json({ error: "Password is incorrect!" });
      } else {
        const accessToken = createTokens(user);

        res.cookie("access-token", accessToken, {
          maxAge: 60 * 60 * 24 * 30 * 1000,
          httpOnly: true,
        });

        res.json({ message: "User is Logged in" });
      }
    });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }

});

//accessing the logged-in user's profile
app.get("/users/profile", validateToken, (req, res) => {
  res.json("profile");
});




//logout endpoint
app.get('/users/logout', (req, res) => {
  res.cookie("access-token", '', { maxAge: 1 });
  res.json({ message: "User has been logged out" })
})








app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
