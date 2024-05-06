import { Router } from "express";

import mw from "../middlewares/mw.js";

import UsersController from "../controllers/UsersController.js";

const usersController = new UsersController();

const usersRouter = new Router();

usersRouter.post("/checkuser", mw.authApp, usersController.checkUser);

//usersRouter.post("/addsuperadmin", usersController.addSuperAdmin);

usersRouter.post("/register", mw.auth, mw.accessSuperAdmin, usersController.register);

usersRouter.post("/login", mw.authApp, usersController.login);

usersRouter.post("/switchrole", mw.auth, usersController.switchRole);

usersRouter.post("/logout", mw.auth, usersController.logout);

usersRouter.post("/logoutalldevices", usersController.logoutAllDevices);

usersRouter.post("/getuser", mw.auth, mw.accessHr, usersController.getUser);

usersRouter.post("/getuserbyapp", mw.authApp, usersController.getUserByApp);

usersRouter.post("/getusers", mw.auth, mw.accessHr, usersController.getUsers);

usersRouter.post("/getusersbyapp", mw.authApp, usersController.getUsersByApp);

usersRouter.post("/getusersdatabyapp", mw.authApp, usersController.getUsersDataByApp);

usersRouter.post("/getallusers", mw.auth, mw.accessAdmin, usersController.getAllUsers);

usersRouter.post("/getusersbystatus0", mw.auth, mw.accessHr, usersController.getUsersByStatus0);

usersRouter.post("/getusersbystatus1", mw.auth, mw.accessHr, usersController.getUsersByStatus1);

usersRouter.post("/getusersbybanstatus0", mw.auth, mw.accessHr, usersController.getUsersByBanStatus0);

usersRouter.post("/getusersbybanstatus1", mw.auth, mw.accessHr, usersController.getUsersByBanStatus1);

usersRouter.post("/getusersbycountry", mw.auth, mw.accessHr, usersController.getUsersByCountry);

usersRouter.post("/getusersbydeletedat", mw.auth, mw.accessHr, usersController.getUsersByDeletedAt);

usersRouter.put("/updateuserfirstname", mw.auth, mw.accessAdmin, usersController.updateUserFirstName);

usersRouter.put("/updateuserfirstnamebyhr", mw.auth, mw.accessHr, usersController.updateUserFirstNameByHr);

usersRouter.put("/updateusermiddlename", mw.auth, mw.accessAdmin, usersController.updateUserMiddleName);

usersRouter.put("/updateusermiddlenamebyhr", mw.auth, mw.accessHr, usersController.updateUserMiddleNameByHr);

usersRouter.put("/updateuserlastname", mw.auth, mw.accessAdmin, usersController.updateUserLastName);

usersRouter.put("/updateuserlastnamebyhr", mw.auth, mw.accessHr, usersController.updateUserLastNameByHr);

usersRouter.put("/updateusernickname", mw.auth, mw.accessAdmin, usersController.updateUserNickName);

usersRouter.put("/updateusernicknamebyuser", mw.auth, mw.accessUser, usersController.updateUserNickNameByUser);

usersRouter.put("/updateuseremail", mw.auth, mw.accessSuperAdmin, usersController.updateUserEmail);

usersRouter.put("/updateuserpassword", mw.auth, mw.accessSuperAdmin, usersController.updateUserPassword);

usersRouter.put("/updateuserroles", mw.auth, mw.accessSuperAdmin, usersController.updateUserRoles);

usersRouter.put("/updateuserstatus0", mw.auth, mw.accessSuperAdmin, usersController.updateUserStatus0);

usersRouter.put("/updateuserstatus1", mw.auth, mw.accessSuperAdmin, usersController.updateUserStatus1);

usersRouter.put("/updateuserbanstatus0", mw.auth, mw.accessSuperAdmin, usersController.updateUserBanStatus0);

usersRouter.put("/updateuserbanstatus1", mw.auth, mw.accessSuperAdmin, usersController.updateUserBanStatus1);

usersRouter.put("/updateuserimage", mw.auth, mw.accessSuperAdmin, usersController.updateUserImage);

usersRouter.put("/updateuserimagebyuser", mw.auth, mw.accessSuperAdmin, usersController.updateUserImageByUser);

usersRouter.put("/updateuserabout", mw.auth, mw.accessSuperAdmin, usersController.updateUserAbout);

usersRouter.put("/updateuseraboutbyuser", mw.auth, mw.accessSuperAdmin, usersController.updateUserAboutByUser);

usersRouter.put("/updateusercountry", mw.auth, mw.accessSuperAdmin, usersController.updateUserCountry);

usersRouter.put("/updateusercountrybyhr", mw.auth, mw.accessSuperAdmin, usersController.updateUserCountryByHr);

usersRouter.put("/updateusercontact", mw.auth, mw.accessSuperAdmin, usersController.updateUserContact);

usersRouter.put("/updateusercontactbyhr", mw.auth, mw.accessSuperAdmin, usersController.updateUserContactByHr);

usersRouter.put("/updateusertokens", mw.auth, mw.accessSuperAdmin, usersController.updateUserTokens);

usersRouter.put("/updateuserassignmentuser0", mw.auth, mw.accessAdmin, usersController.updateUserAssignmentUser0);

usersRouter.put("/updateuserassignmentuser1", mw.auth, mw.accessAdmin, usersController.updateUserAssignmentUser1);

usersRouter.put("/updateuserwebsitedata", mw.auth, mw.accessAdmin, usersController.updateUserWebsiteData);

usersRouter.put("/updateuserdeletedat", mw.auth, mw.accessSuperAdmin, usersController.updateUserDeletedAt);

usersRouter.put("/updateuserdeletedatnull", mw.auth, mw.accessSuperAdmin, usersController.updateUserDeletedAtNull);

usersRouter.put("/updateusersroles", mw.auth, mw.accessSuperAdmin, usersController.updateUsersRoles);

usersRouter.put("/updateusersstatus0", mw.auth, mw.accessSuperAdmin, usersController.updateUsersStatus0);

usersRouter.put("/updateusersstatus1", mw.auth, mw.accessSuperAdmin, usersController.updateUsersStatus1);

usersRouter.put("/updateusersbanstatus0", mw.auth, mw.accessSuperAdmin, usersController.updateUsersBanStatus0);

usersRouter.put("/updateusersbanstatus1", mw.auth, mw.accessSuperAdmin, usersController.updateUsersBanStatus1);

usersRouter.put("/updateusersdeletedat", mw.auth, mw.accessSuperAdmin, usersController.updateUsersDeletedAt);

usersRouter.put("/updateusersdeletedatnull", mw.auth, mw.accessSuperAdmin, usersController.updateUsersDeletedAtNull);

//usersRouter.delete("/deleteuser", mw.auth, mw.accessSuperAdmin, usersController.deleteUser);

//usersRouter.delete("/deleteusers", mw.auth, mw.accessSuperAdmin, usersController.deleteUsers);

//usersRouter.delete("/deleteallusers", mw.auth, mw.accessSuperAdmin, usersController.deleteAllUsers);

//usersRouter.get('/createtable', usersController.createTable);

//usersRouter.get('/droptable', usersController.dropTable);

//usersRouter.get('/test', usersController.test);

//usersRouter.get('/app', usersController.app);

//usersRouter.get('/cron', usersController.cron);

//usersRouter.get('/jwt', usersController.jwt);

export default usersRouter