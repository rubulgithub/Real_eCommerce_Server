import { Router } from "express";
import {
  getMyEcomProfile,
  getMyOrders,
  updateEcomProfile,
} from "../controllers/profile.controllers.js";
import { verifyJWT } from "../middlewares/auth.middlewares.js";
import { updateEcomProfileValidator } from "../validators/profile.validators.js";
import { validate } from "../validators/validate.js";

const router = Router();

router.use(verifyJWT);

router
  .route("/")
  .get(getMyEcomProfile)
  .patch(updateEcomProfileValidator(), validate, updateEcomProfile);

router.route("/my-orders").get(getMyOrders);

export default router;
