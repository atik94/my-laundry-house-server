const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const port = process.env.PORT || 5000;

const app = express();

// middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.z8kj7tg.mongodb.net/?retryWrites=true&w=majority`;
console.log(uri);
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send("unauthorized access");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN, function (err, decoded) {
    if (err) {
      return res.status(403).send({ message: "forbidden access" });
    }
    req.decoded = decoded;
    next();
  });
}

async function run() {
  try {
    const usersCollection = client.db("my-laundry-house").collection("users");
    const servicesCollection = client.db("my-laundry-house").collection("services");
    const reviewsCollection = client.db("my-laundry-house").collection("review");

    // NOTE: make sure you use verifyAdmin after verifyJWT
    const verifyAdmin = async (req, res, next) => {
      const decodedEmail = req.decoded.email;
      const query = { email: decodedEmail };
      const user = await usersCollection.findOne(query);

      if (user?.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    // NOTE: make sure you use verifyUser after verifyJWT
    const verifyBuyer = async (req, res, next) => {
      const decodedEmail = req.decoded.email;
      const query = { email: decodedEmail };
      const user = await usersCollection.findOne(query);

      if (user?.role !== "buyers") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    app.get("/jwt", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user) {
        const token = jwt.sign({ email }, process.env.ACCESS_TOKEN, { expiresIn: "1h" });
        return res.send({ accessToken: token });
      }
      res.status(403).send({ accessToken: "" });
    });

    // Save Users Both EmailPassword and GoogleSignIn based authentication.
    app.post("/users", async (req, res) => {
      const user = req.body;
      const query = {
        email: user.email,
      };
      const alreadyHasEmail = await usersCollection.find(query).toArray();
      if (alreadyHasEmail.length) {
        const message = "You already have an email";
        return res.send({ acknowledged: false, message });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    //All Users Api
    app.get("/users", async (req, res) => {
      const query = {};
      const users = await usersCollection.find(query).toArray();
      res.send(users);
    });

    //Making pending to users.
    app.patch("/users/:id", async (req, res) => {
      const id = req.params.id;
      const role = req.body.role;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          role: role,
        },
      };
      const result = await usersCollection.updateOne(query, updatedDoc);
      res.send(result);
    });

    //Admin Role Api
    app.get("/users/admin/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      res.send({ isAdmin: user?.role === "admin" });
    });

    //Users Role Api
    app.get("/users/user/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      res.send({ isUser: user?.role === "user" });
    });

    // All Buyers api
    app.get("/buyers", verifyJWT, verifyAdmin, async (req, res) => {
      const query = { role: "buyers" };
      const buyers = await usersCollection.find(query).toArray();
      console.log(buyers);
      res.send(buyers);
    });

    //Users Delete Api
    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(filter);
      res.send(result);
    });

    //Service Api
    app.post("/services", verifyJWT, verifyAdmin, async (req, res) => {
      const query = req.body;
      const options = await servicesCollection.insertOne(query);
      res.send(options);
    });

    // Get service api
    app.get("/services", async (req, res) => {
      const query = {};
      const cursor = servicesCollection.find(query).sort({ title: -1 });
      const services = await cursor.toArray();
      res.send(services);
    });

    app.get("/services/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const service = await servicesCollection.findOne(query);
      res.send(service);
    });

    //Review Api
    app.post("/reviews", async (req, res) => {
      const review = req.body;
      const result = await reviewsCollection.insertOne(review);
      res.send(result);
    });

    app.get("/reviews", async (req, res) => {
      let query = {};
      if (req.query.email) {
        query = {
          email: req.query.email,
        };
      }

      if (req.query.id) {
        query = {
          service: req.query.id,
        };
      }
      const cursor = reviewsCollection.find(query);
      const reviews = await cursor.toArray();
      res.send(reviews);
    });

    app.get("/reviews/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const review = await reviewsCollection.findOne(query);
      res.send(review);
    });

    app.delete("/reviews/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await reviewsCollection.deleteOne(query);
      res.send(result);
    });

    //Review update api create
    app.put("/reviews/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const review = req.body;
      const option = { upsert: true };
      const updatedReview = {
        $set: {
          message: review.message,
        },
      };
      const result = await reviewsCollection.updateOne(filter, updatedReview, option);
      res.send(result);
    });
  } finally {
  }
}
run().catch(console.log);

app.get("/", async (req, res) => {
  res.send("my laundry house server is running");
});

app.listen(port, () => console.log(`my laundry house server running on ${port}`));
