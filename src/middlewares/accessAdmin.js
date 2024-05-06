import * as dotenv from "dotenv";

dotenv.config();

const accessAdmin = async (req, res, next) => {

    const user_id = req?.user_id ? req?.user_id : 0;

    const u_id = req?.u_id ? req?.u_id : '';

    const email = req?.email ? req?.email : '';

    const roles = req?.roles ? req?.roles : [];

    const accessRoles = [
        "SUPERADMIN",
        "ADMIN",
        "MANAGER"
    ];

    try {

        const accessArray = roles.map((role) => accessRoles.includes(role)).find((value) => value === true);

        if (!accessArray) return res.json({ error: true, data: "Unauthorized role!" });

        req.user_id = user_id;

        req.u_id = u_id;

        req.email = email;

        req.roles = roles;

        await next();

    } catch (error) {

        console.log(error);

        return res.json({ error: true, data: error });
    }

}

export default accessAdmin