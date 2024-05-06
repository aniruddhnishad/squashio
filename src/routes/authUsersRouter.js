import { Router } from "express";

import mw from "../middlewares/mw.js";

import AuthUsersController from "../controllers/AuthUsersController.js";

const authUsersController = new AuthUsersController();

const authUsersRouter = new Router();

authUsersRouter.post("/authusersapi", mw.auth, authUsersController.authUsersApi);

authUsersRouter.post("/authassignmentsapi", mw.auth, authUsersController.authAssignmentsApi);

authUsersRouter.post("/authbacklinksapi", mw.auth, authUsersController.authBacklinksApi);

authUsersRouter.post("/authfreelancersapi", mw.auth, authUsersController.authFreelancersApi);

authUsersRouter.post("/authfreelancersapibyfreelancer", mw.authApp, authUsersController.authFreelancersApiByFreelancer);

authUsersRouter.post("/authclientsapi", mw.auth, authUsersController.authClientsApi);

authUsersRouter.post("/authclientsapibyclient", mw.authApp, authUsersController.authClientsApiByClient);

authUsersRouter.post("/authassignmentsemailapi", mw.auth, authUsersController.authAssignmentsEmailApi);

authUsersRouter.post("/authlogiccirclecoemailsapi", mw.auth, authUsersController.authLogiccirclecoEmailsApi);

authUsersRouter.post("/authlogiccirclenetemailsapi", mw.auth, authUsersController.authLogiccirclenetEmailsApi);

authUsersRouter.post("/authtestapi", mw.auth, authUsersController.authTestApi);

//authUsersRouter.post('/test', authUsersController.test);

export default authUsersRouter