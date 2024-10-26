import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import { rateLimit } from "express-rate-limit";
import session from "express-session";
import fs from "fs";
import { createServer } from "http";
import passport from "passport";
import path from "path";
import requestIp from "request-ip";
import { Server } from "socket.io";
import swaggerUi from "swagger-ui-express";
import { fileURLToPath } from "url";
import YAML from "yaml";
import { DB_NAME } from "./constants.js";
import { dbInstance } from "./db/index.js";
import morganMiddleware from "./logger/morgan.logger.js";
import { initializeSocketIO } from "./socket/index.js";
import { ApiError } from "./utils/ApiError.js";
import { ApiResponse } from "./utils/ApiResponse.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const file = fs.readFileSync(path.resolve(__dirname, "./swagger.yaml"), "utf8");
const swaggerDocument = YAML.parse(
  file?.replace(
    "- url: ${{server}}",
    `- url: ${process.env.FREEAPI_HOST_URL || "http://localhost:8080"}/api/v1`
  )
);

const app = express();

const httpServer = createServer(app);

const io = new Server(httpServer, {
  pingTimeout: 60000,
  cors: {
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  },
});

app.set("io", io); // using set method to mount the `io` instance on the app to avoid usage of `global`

// global middlewares
app.use(
  cors({
    origin:
      process.env.CORS_ORIGIN === "*"
        ? "*" // This might give CORS error for some origins due to credentials set to true
        : process.env.CORS_ORIGIN?.split(","), // For multiple cors origin for production. Refer https://github.com/hiteshchoudhary/apihub/blob/a846abd7a0795054f48c7eb3e71f3af36478fa96/.env.sample#L12C1-L12C12
    credentials: true,
  })
);

app.use(requestIp.mw());

// Rate limiter to avoid misuse of the service and avoid cost spikes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000, // Limit each IP to 500 requests per `window` (here, per 15 minutes)
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req, res) => {
    return req.clientIp; // IP address from requestIp.mw(), as opposed to req.ip
  },
  handler: (_, __, ___, options) => {
    throw new ApiError(
      options.statusCode || 500,
      `There are too many requests. You are only allowed ${
        options.max
      } requests per ${options.windowMs / 60000} minutes`
    );
  },
});

// Apply the rate limiting middleware to all requests
app.use(limiter);

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public")); // configure static file to save images locally
app.use(cookieParser());

// required for passport
app.use(
  session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  })
); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

app.use(morganMiddleware);
// api routes
import { errorHandler } from "./middlewares/error.middlewares.js";
import healthcheckRouter from "./routes/healthcheck.routes.js";

// * App routes
import userRouter from "./routes/user.routes.js";

import addressRouter from "./routes/address.routes.js";
import cartRouter from "./routes/cart.routes.js";
import categoryRouter from "./routes/category.routes.js";
import couponRouter from "./routes/coupon.routes.js";
import orderRouter from "./routes/order.routes.js";
import productRouter from "./routes/product.routes.js";
import ecomProfileRouter from "./routes/profile.routes.js";

// * healthcheck
app.use("/api/v1/healthcheck", healthcheckRouter);

// * App apis
app.use("/api/v1/users", userRouter);

app.use("/api/v1/ecommerce/categories", categoryRouter);
app.use("/api/v1/ecommerce/addresses", addressRouter);
app.use("/api/v1/ecommerce/products", productRouter);
app.use("/api/v1/ecommerce/profile", ecomProfileRouter);
app.use("/api/v1/ecommerce/cart", cartRouter);
app.use("/api/v1/ecommerce/orders", orderRouter);
app.use("/api/v1/ecommerce/coupons", couponRouter);

initializeSocketIO(io);

// // ! 🚫 Danger Zone
// app.delete("/api/v1/reset-db", avoidInProduction, async (req, res) => {
//   if (dbInstance) {
//     // Drop the whole DB
//     await dbInstance.connection.db.dropDatabase({
//       dbName: DB_NAME,
//     });

//     const directory = "./public/images";

//     // Remove all product images from the file system
//     fs.readdir(directory, (err, files) => {
//       if (err) {
//         // fail silently
//         logger.error("Error while removing the images: ", err);
//       } else {
//         for (const file of files) {
//           if (file === ".gitkeep") continue;
//           fs.unlink(path.join(directory, file), (err) => {
//             if (err) throw err;
//           });
//         }
//       }
//     });
//     // remove the seeded users if exist
//     fs.unlink("./public/temp/seed-credentials.json", (err) => {
//       // fail silently
//       if (err) logger.error("Seed credentials are missing.");
//     });
//     return res
//       .status(200)
//       .json(new ApiResponse(200, null, "Database dropped successfully"));
//   }
//   throw new ApiError(500, "Something went wrong while dropping the database");
// });

// * API DOCS
// ? Keeping swagger code at the end so that we can load swagger on "/" route
app.use(
  "/",
  swaggerUi.serve,
  swaggerUi.setup(swaggerDocument, {
    swaggerOptions: {
      docExpansion: "none", // keep all the sections collapsed by default
    },
    customSiteTitle: "FreeAPI docs",
  })
);

// common error handling middleware
app.use(errorHandler);

export { httpServer };
