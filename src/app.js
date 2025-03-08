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
    origin:
      process.env.CORS_ORIGIN?.split(",").map((origin) => origin.trim()) || [],
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

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.clientIp,
  handler: (req, res) => {
    res
      .status(429)
      .json(new ApiResponse(429, "Too many requests. Try again later.", null));
  },
});

app.use(limiter);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

// Session Middleware (Security Enhanced)
app.use(cookieParser());

app.use(
  session({
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Secure in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax", // Allow cross-site cookies
    },
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
