import dotenv from "dotenv";
dotenv.config();

import jsonServer from "json-server";
import path from "path";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import ShortUniqueId from "short-unique-id";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { LowSync } from "lowdb";
import { JSONFileSync } from "lowdb/node";

const cors = require("cors");
import protectedRoutesConfig from "./serverConfig.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uid = new ShortUniqueId({ length: 10 });

const dbFile = process.env.DB || "db.json";
const serverPort = process.env.REACT_APP_JSON_SERVER_PORT || 9090;
const staticDirectoryName = process.env.STATIC_FILES || "server-files";

const file = path.join(__dirname, dbFile);
const adapter = new JSONFileSync(file);
const db = new LowSync(adapter);

// db.read();
// db.data.users.push({ three: "four" });
// db.write();

const server = jsonServer.create();

// foreign key suffix as second parameter to the module. Below code sets it to dummy
// it fixes delete problem but causes expansion problems.
const router = jsonServer.router(join(__dirname, dbFile), {
  foreignKeySuffix: "dummy",
});

const staticDir = path.join(__dirname, staticDirectoryName);
const middlewares = jsonServer.defaults({ static: staticDir });

server.use(middlewares);
server.use(jsonServer.bodyParser);

// config
const protectedRoutes = protectedRoutesConfig.protectedRoutes;

// Authorization logic
server.use((req, res, next) => {
  let NeedsAuthorization = false;

  for (let i = 0; i < protectedRoutes.length; i++) {
    let { route, methods } = protectedRoutes[i];

    // if ((route === 'GET' && ))

    if (req.url.startsWith(route)) {
      if (methods.includes(req.method)) {
        NeedsAuthorization = true;
        break;
      }
    }
  }

  if (NeedsAuthorization) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!authHeader || !token)
      return res
        .status(403)
        .send(
          "Its a protected route/method. You need an auth token to access it."
        );

    jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET ||
        "62a798775294eda38d9d5bdb57cfae9d1fff7a550c11c06ef2888fc1af641c09291d17f07f04156356fd86223256fbcc026e791a80a876fe7b14d4ba30ec185d",
      (err, user) => {
        if (err)
          return res
            .status(403)
            .send("Some error occurred wile verifying token.");
        req.user = user;
        next();
      }
    );
  } else {
    next();
  }
});

// default id & created at
server.use((req, res, next) => {
  if (req.method === "POST") {
    req.body.createdAt = Date.now();
  }

  if (req.method === "POST" && !req.body.id) {
    req.body.id = uid();
  }

  if (req.method === "POST" && req.user && !req.body.userId) {
    req.body.userId = req.user.id;
  }

  next();
});

// registration logic
server.post("/register", (req, res) => {
  if (
    !req.body ||
    !req.body.username ||
    !req.body.password ||
    !req.body.email
  ) {
    return res
      .status(400)
      .send("Bad request, requires username, password & email.");
  }

  db.read();
  const users = db.data.users;
  let largestId = 0;
  users.forEach((user) => {
    if (user.id > largestId) largestId = user.id;
  });

  const hashedPassword = bcrypt.hashSync(req.body.password, 10);
  const newId = largestId + 1;
  const newUserData = {
    username: req.body.username,
    password: hashedPassword,
    email: req.body.email,
    firstname: req.body.firstname || "",
    lastname: req.body.lastname || "",
    avatar: req.body.avatar || "",
    createdAt: Date.now(),
    id: newId,
  };

  db.data.users.push(newUserData);

  db.write();

  res.status(201).send(newUserData);
});

// login/sign in logic
server.post("/login", (req, res) => {
  if (!req.body || !req.body.username || !req.body.password) {
    return res
      .status(400)
      .send("Bad request, requires username & password both.");
  }

  db.read();
  const users = db.data.users;
  const user = users.find((u) => u.username === req.body.username);
  if (user == null) {
    return res.status(400).send(`Cannot find user: ${req.body.username}`);
  }

  if (bcrypt.compareSync(req.body.password, user.password)) {
    // creating JWT token
    const accessToken = generateAccessToken(user);
    return res.send({
      accessToken: accessToken,
      user: user,
    });
  } else {
    res.send("Not allowed, name/password mismatch.");
  }
});

function generateAccessToken(user) {
  return jwt.sign(
    user,
    process.env.ACCESS_TOKEN_SECRET ||
      "62a798775294eda38d9d5bdb57cfae9d1fff7a550c11c06ef2888fc1af641c09291d17f07f04156356fd86223256fbcc026e791a80a876fe7b14d4ba30ec185d",
    { expiresIn: "3h" }
  );
}

// To modify responses, overwrite router.render method:
// In this example, returned resources will be wrapped in a body property
// router.render = (req, res) => {
//   res.jsonp({
//     body: res.locals.data,
//   });
// };

server.use(router);

let nodeEnv = process.env.NODE_ENV || "production";

sgMail.setApiKey(process.env.SENDGRID_API_SERECT_KEY);
server.use(cors());

server.post("/sendmail", (req, res) => {
  const { patientEmail, ccMail, bccMail, doctorName, patientName } = req.body;
  const msg = {
    to: patientEmail, // Change to your recipient
    from: {
      name: "Rucja/Cancer Unwired",
      email: "shankartrailmail@gmail.com",
    }, // Change to your verified sender
    cc: ccMail, // Add this line
    bcc: bccMail, // And this line
    subject: `Hi ${patientName}, You have been added as a patient`,
    text: "and easy to do anywhere, even with Node.js",
    html: `<!DOCTYPE html>
      <html>
      <head>
          <title>Rucja Medical Application</title>
          <style>
              body {
                  font-family: Arial, sans-serif;
              }
              .header {
                  text-align: center;
                  padding: 10px;
                  background-color: #f8f9fa;
              }
              .content {
                  margin: 20px;
                  text-align:center
              }
          </style>
      </head>
      <body>
          <div class="header">
              <h1>Welcome to Rucja Medical Application</h1>
          </div>
          <div class="content">
              <p>${doctorName} Doctor has added you as a patient.</p>
          </div>
      </body>
      </html>
      `,
  };

  sgMail
    .send(msg)
    .then(() => {
      console.log("Email sent");
      res
        .status(200)
        .send({ success: true, message: "Email sent successfully" });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send("Error sending email");
    });
});
server.post("/patient-added-mail", (req, res) => {
  const { patientEmail, ccMail, bccMail, doctorName, patientName } = req.body;
  const emailMessage = {
    to: patientEmail,
    from: "shankartrailmail@gmail.com",
    cc: ccMail,
    bcc: bccMail,
    subject: `Hi ${patientName}, You have been added patient`,
    text: "",
    html: `<!DOCTYPE html>
    <html>
    <head>
        <title>Rucja Medical Application</title>
        <style>
            body {
                font-family: Arial, sans-serif;
            }
            .header {
                text-align: center;
                padding: 10px;
                background-color: #f8f9fa;
            }
            .content {
                margin: 20px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to Rucja Medical Application</h1>
        </div>
        <div class="content">
            <p>${doctorName} Doctor has added you as a patient.</p>
        </div>
    </body>
    </html>
    `,
  };

  sgMail
    .send(emailMessage)
    .then((response) => {
      console.log("SendGrid Response:", response);
      // Check for success or handle response as needed
      res
        .status(200)
        .send({ success: true, message: "Email sent successfully" });
    })
    .catch((error) => {
      console.error("SendGrid Error:", error);
      // Handle the error and send an appropriate response
      res.status(500).send({ success: false, message: "Error sending email" });
    });
});

server.post("/meeting-email-confirmation-patient", (req, res) => {
  const {
    patientEmail,
    ccMail,
    bccMail,
    doctorName,
    patientName,
    appointmentDate,
    appointmentTime,
    password,
    appointmentID,
  } = req.body;
  const meetingLink =
    "https://cancer-unwired-meetings-37zgb57m5-shankar-43s-projects.vercel.app/";

  const msg = {
    to: patientEmail,
    cc: ccMail,
    bcc: bccMail,
    from: {
      name: "Dr. " + doctorName,
      email: "shankartrailmail@gmail.com", // Doctor's email address
    },
    subject: `Hi ${patientName}, You have an appointment scheduled`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
          <title>Appointment Confirmation</title>
          <style>
              body {
                  font-family: Arial, sans-serif;
              }
              .header {
                  text-align: center;
                  padding: 10px;
                  background-color: #f5f5f5;
              }
              h1 {
                  color: #5b0374;
              }
              .content {
                  margin: 0 auto;
                  width: 60%;
                  text-align: left;
                  padding: 20px;
                  border: 1px solid #ccc;
                  border-radius: 10px;
                  margin-top: 50px;
              }
              .meeting-details {
                  margin-top: 30px;
              }
              .send-meeting-section {
                  text-align: center;
                  margin-top: 20px;
              }
              .send-meeting-button {
                  background-color: #9426b2;
                  color: white;
                  border: none;
                  padding: 10px 20px;
                  border-radius: 5px;
                  text-decoration: none;
              }
          </style>
      </head>
      <body>
          <div class="header">
              <h1>Cancer Unwired Meeting</h1>
          </div>
          <div class="content">
              <h4>Hello Mr. ${patientName},</h4>
              <p>You have an upcoming appointment with Dr.${doctorName}.</p>
              <div class="meeting-details">
                  <h4>Meeting Details:</h4>
                  <p>Meeting/SessionID: ${appointmentID}</p>
                  <p>password: ${password}</p>
                  <p>Date: ${appointmentDate}</p>
                  <p>Time: ${appointmentTime}</p>
                  <p>Meeting Link: ${meetingLink}?userName=${patientName}</p>
              </div>
              <div class="send-meeting-section">
                  <button class="send-meeting-button">
                  <a href="${meetingLink}?sessionID=${appointmentID}&userName=${patientName}&password=${password}&role=0" style="color: white; text-decoration: none;">Join Meeting</a>
                  </button>
              </div>
          </div>
      </body>
      </html>
    `,
  };

  sgMail
    .send(msg)
    .then(() => {
      console.log("Email sent to patient");
      res
        .status(200)
        .send({ success: true, message: "Email sent successfully" });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send("Error sending email to patient");
    });
});

server.post("/meeting-email-confirmation-doctor", (req, res) => {
  const {
    doctorEmail,
    ccMail,
    bccMail,
    doctorName,
    patientName,
    appointmentID,
    appointmentDate,
    appointmentTime,
    password,
  } = req.body;
  const meetingLink =
    "https://cancer-unwired-meetings-37zgb57m5-shankar-43s-projects.vercel.app/";

  const msg = {
    to: doctorEmail,
    cc: ccMail,
    bcc: bccMail,
    from: {
      name: "Cancer Unwired",
      email: "shankartrailmail@gmail.com", // Sender's email address
    },
    subject: `Hi Dr. ${doctorName}, You have an upcoming appointment with ${patientName}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
          <title>Appointment Confirmation</title>
          <style>
              body {
                  font-family: Arial, sans-serif;
              }
              .header {
                  text-align: center;
                  padding: 10px;
                  background-color: #f5f5f5;
              }
              h1 {
                  color: #5b0374;
              }
              .content {
                  margin: 0 auto;
                  width: 60%;
                  text-align: left;
                  padding: 20px;
                  border: 1px solid #ccc;
                  border-radius: 10px;
                  margin-top: 50px;
              }
              .meeting-details {
                  margin-top: 30px;
              }
              .send-meeting-section {
                  text-align: center;
                  margin-top: 20px;
              }
              .send-meeting-button {
                  background-color: #9426b2;
                  color: white;
                  border: none;
                  padding: 10px 20px;
                  border-radius: 5px;
                  text-decoration: none;
              }
          </style>
      </head>
      <body>
          <div class="header">
              <h1>Cancer Unwired Meeting</h1>
          </div>
          <div class="content">
              <h4>Hello Dr. ${doctorName},</h4>
              <p>You have an upcoming appointment with ${patientName}.</p>
              <div class="meeting-details">
                  <h4>Meeting Details:</h4>
                  <p>Meeting/SessionID: ${appointmentID}</p>
                  <p>password: ${password}</p>
                  <p>Date: ${appointmentDate}</p>
                  <p>Time: ${appointmentTime}</p>
                  <p>Meeting Link: ${meetingLink}?sessionID=${appointmentID}&userName=${doctorName}&password=${password}&role=1</p>
              </div>
              <div class="send-meeting-section">
                  <button class="send-meeting-button">
                      <a href="${meetingLink}?sessionID=${appointmentID}&userName=${doctorName}&password=${password}&role=1" style="color: white; text-decoration: none;">Join Meeting</a>
                  </button>
              </div>
          </div>
      </body>
      </html>
    `,
  };

  sgMail
    .send(msg)
    .then((res) => {
      console.log("Email sent to doctor");
      res
        .status(200)
        .send({ success: true, message: "Email sent successfully" });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).send("Error sending email to doctor");
    });
});

const PORT =
  nodeEnv == "development"
    ? `http://localhost:${+serverPort}/`
    : `PORT: ${+serverPort}`;

server.listen(+serverPort, () => {
  console.log(`JSON Server is running at ${PORT} in ${nodeEnv} ENV.`);
});
