import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import stripePackage from "stripe";

env.config();

const app = express();
const port = process.env.LOCALHOST_PORT;
const saltRounds = 10;
const defaultPhotoUrl = "/assets/images/defaultprofileimage.jpg";

var loginPasswordMatch = false;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
    store: new session.MemoryStore(),
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

const stripe = stripePackage(process.env.STRIPE_SECRET_KEY);

app.get("/", async (req, res) => {
  try {
    const isLoggedIn = req.isAuthenticated();
    let userPhotoUrl = null;

    if (isLoggedIn) {
      userPhotoUrl = req.user.photo_path;
    }

    const dogsResult = await db.query(`
        SELECT MIN(d.id) AS dog_id, d.breed, COUNT(*) AS total_sales, 
        d.price AS price_dog, d.age, d.description, d.image_url
        FROM Dog d
        JOIN Sale s ON d.id = s.dog_id
        GROUP BY d.breed, d.price, d.age, d.description, d.image_url
        ORDER BY total_sales DESC
        LIMIT 3;
      `);
    const topSellingDogs = dogsResult.rows;

    const testimonialsResult = await db.query(`
        SELECT * FROM sale 
        ORDER BY sale_date DESC 
        LIMIT 5
      `);
    const testimonials = testimonialsResult.rows;

    res.render("index.ejs", {
      isLoggedIn,
      userPhotoUrl,
      listItems: topSellingDogs,
      testimonials,
    });
  } catch (err) {
    console.error("Error fetching data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/dogs", async (req, res) => {
  try {
    const isLoggedIn = req.isAuthenticated();
    let userPhotoUrl = null;

    if (isLoggedIn) {
      userPhotoUrl = req.user.photo_path;
    }
    const dogs = await db.query("SELECT * FROM Dog ORDER BY id ASC");

    res.render("product.ejs", {
      isLoggedIn,
      userPhotoUrl,
      dogs: dogs.rows,
      noDogsFound: false,
    });
  } catch (err) {
    console.error("Error fetching dog data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/dogs/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const isLoggedIn = req.isAuthenticated();
    let userPhotoUrl = null;

    if (isLoggedIn) {
      userPhotoUrl = req.user.photo_path;
    }

    const result = await db.query("SELECT * FROM Dog WHERE id = $1", [id]);

    if (!result) {
      res.status(404).send("Dog not found");
      return;
    }

    res.render("detail.ejs", {
      isLoggedIn,
      userPhotoUrl,
      dogs: result.rows[0],
    });
  } catch (err) {
    console.error("Error fetching dog details:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/about", (req, res) => {
  const isLoggedIn = req.isAuthenticated();
  let userPhotoUrl = null;

  if (isLoggedIn) {
    userPhotoUrl = req.user.photo_path;
  }
  res.render("about.ejs", { isLoggedIn, userPhotoUrl });
});

app.get("/contact", (req, res) => {
  const isLoggedIn = req.isAuthenticated();
  let userPhotoUrl = null;

  if (isLoggedIn) {
    userPhotoUrl = req.user.photo_path;
  }
  res.render("contact.ejs", { isLoggedIn, userPhotoUrl });
});

app.get("/login", (req, res) => {
  res.render("login.ejs", { loginPasswordMatch });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/forgot-password", (req, res) => {
  var passwordMatch = false;
  var successMatch = false;
  res.render("forgotpassword.ejs", { passwordMatch, successMatch });
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/furryfriends",
  passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.get("/success", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const user = req.user;
      const buyerName = user.firstname;
      const buyerEmail = user.email;
      const buyerPhoto = user.photo_path;

      const dogId = req.session.dogId;

      const dogQuery = "SELECT * FROM dog WHERE id = $1";
      const { rows: dogRows } = await db.query(dogQuery, [dogId]);
      const dog = dogRows[0];

      const saleQuery = `
          INSERT INTO sale (sale_date, buyer_name, buyer_email, dog_id, image_url)
          VALUES (CURRENT_DATE, $1, $2, $3, $4)
          RETURNING *`;
      const saleValues = [buyerName, buyerEmail, dogId, buyerPhoto];
      const { rows: saleRows } = await db.query(saleQuery, saleValues);
      const sale = saleRows[0];
      const saleId = saleRows[0].id;

      req.session.saleId = saleId;

      const updateStockQuery = `
          UPDATE dog
          SET stock = stock - 1
          WHERE id = $1`;
      await db.query(updateStockQuery, [dogId]);

      res.render("success.ejs");
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Error processing successful checkout:", error);
    res.status(500).send("Error processing successful checkout");
  }
});

app.post("/search", async (req, res) => {
  const searchQuery = req.body.search.toLowerCase();

  try {
    const isLoggedIn = req.isAuthenticated();
    let userPhotoUrl = null;

    if (isLoggedIn) {
      userPhotoUrl = req.user.photo_path;
    }
    const result = await db.query(
      "SELECT * FROM Dog WHERE LOWER(breed) LIKE '%' || $1 || '%'",
      [searchQuery.toLowerCase()]
    );

    if (result.rows.length > 0) {
      res.render("product.ejs", {
        isLoggedIn,
        userPhotoUrl,
        dogs: result.rows,
        noDogsFound: false,
      });
    } else {
      res.render("product.ejs", { 
        isLoggedIn,
        userPhotoUrl,
        noDogsFound: true,
       });
    }
  } catch (err) {
    console.error("Error searching for dogs:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const firstName = req.body.firstname;
  const lastName = req.body.lastname;
  const email = req.body.email;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password, photo_path, firstname, lastname) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [email, hash, defaultPhotoUrl, firstName, lastName]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy({ usernameField: "email" }, async function (
    email,
    password,
    cb
  ) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              loginPasswordMatch = false;
              return cb(null, user);
            } else {
              loginPasswordMatch = true;
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.error("Error finding user:", err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/furryfriends",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password, photo_path, firstname, lastname) VALUES ($1, $2, $3, $4, $5)",
            [
              profile.email,
              "google",
              profile.picture,
              profile.given_name,
              profile.family_name,
            ]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.post("/forgot-password", async (req, res) => {
  const email = req.body.email;
  const newPassword = req.body.newPassword;
  const confirmPassword = req.body.confirmPassword;

  if (newPassword === confirmPassword) {
    try {
      bcrypt.hash(newPassword, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "UPDATE users SET password = $1 WHERE email = $2",
            [hash, email]
          );
          if (result.rowCount === 1) {
            res.render("forgotpassword.ejs", {
              passwordMatch: false,
              successMatch: true,
            });
          } else {
            res.sendStatus(404);
          }
        }
      });
    } catch (error) {
      console.error("Error resetting password:", error);
      res.sendStatus(500);
    }
  } else {
    res.render("forgotpassword.ejs", {
      passwordMatch: true,
      successMatch: false,
    });
  }
});

app.post("/create-checkout-session", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const { dogId } = req.body;
      req.session.dogId = dogId;
      const dogQuery = "SELECT breed, price, image_url FROM dog WHERE id = $1";
      const { rows } = await db.query(dogQuery, [dogId]);
      const dog = rows[0];
      const cancelUrl = `http://localhost:3000/dogs/${dogId}`;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        shipping_address_collection: {
          allowed_countries: ["IN"],
        },
        line_items: [
          {
            price_data: {
              currency: "inr",
              product_data: {
                name: dog.breed,
              },
              unit_amount: dog.price * 100,
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        success_url: "http://localhost:3000/success",
        cancel_url: cancelUrl,
      });

      res.redirect(303, session.url);
    } catch (error) {
      console.error("Error creating checkout session:", error);
      res.status(500).send("Error creating checkout session");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/submit-review", async (req, res) => {
  try {
    if (req.isAuthenticated()) {
      const customerReview = req.body.review;
      const saleId = req.session.saleId;

      const updateQuery = `
          UPDATE sale
          SET customer_review = $1
          WHERE id = $2
          RETURNING *`;
      const updateValues = [customerReview, saleId];
      await db.query(updateQuery, updateValues);

      res.redirect("/");
    } else {
      res.redirect("/login");
    }
  } catch (error) {
    console.error("Error submitting review:", error);
    res.status(500).send("Error submitting review");
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
