import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import { rateLimit } from "express-rate-limit";
import session from "express-session";
import { createServer } from "http";
import passport from "passport";
import path from "path";
import requestIp from "request-ip";
import { Server } from "socket.io";
import { fileURLToPath } from "url";
import morganMiddleware from "./logger/morgan.logger.js";
import { initializeSocketIO } from "./socket/index.js";
import { ApiResponse } from "./utils/ApiResponse.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  pingTimeout: 60000,
  cors: {
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  },
});

app.set("io", io);

// Global Middlewares
app.use(
  cors({
    origin:
      process.env.CORS_ORIGIN?.split(",").map((origin) => origin.trim()) || [],
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
app.use(express.static("public"));
app.use(cookieParser());

// required for passport
app.use(
  session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(morganMiddleware);

// API Routes
import { errorHandler } from "./middlewares/error.middlewares.js";
import healthcheckRouter from "./routes/healthcheck.routes.js";
import userRouter from "./routes/user.routes.js";
import addressRouter from "./routes/address.routes.js";
import cartRouter from "./routes/cart.routes.js";
import categoryRouter from "./routes/category.routes.js";
import couponRouter from "./routes/coupon.routes.js";
import orderRouter from "./routes/order.routes.js";
import productRouter from "./routes/product.routes.js";
import ecomProfileRouter from "./routes/profile.routes.js";

app.use("/api/v1/healthcheck", healthcheckRouter);
app.use("/api/v1/users", userRouter);
app.use("/api/v1/ecommerce/categories", categoryRouter);
app.use("/api/v1/ecommerce/addresses", addressRouter);
app.use("/api/v1/ecommerce/products", productRouter);
app.use("/api/v1/ecommerce/profile", ecomProfileRouter);
app.use("/api/v1/ecommerce/cart", cartRouter);
app.use("/api/v1/ecommerce/orders", orderRouter);
app.use("/api/v1/ecommerce/coupons", couponRouter);

// Initialize Socket.IO
initializeSocketIO(io);

// Error Handling Middleware
app.use(errorHandler);

export { httpServer };
