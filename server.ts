import * as fs from "fs";
import * as crypto from "crypto";
const secp256k1 = require("secp256k1");

import * as express from "express";
import * as serveStatic from "serve-static";
import * as compression from "compression";
import * as session from "express-session";
import * as connectMongo from "connect-mongo";
const MongoStore = connectMongo(session);
import * as slug from "slug";
import * as bodyParser from "body-parser";
const postParser = bodyParser.urlencoded();

export let app = express();
app.use(compression());

///
/// Mongoose
///
import * as mongoose from "mongoose";
(<any>mongoose).Promise = global.Promise;
mongoose.connect("mongodb://localhost/gatekeeper");
app.use(session({
	secret: JSON.parse(fs.readFileSync("keys.json", "utf8")).sessionSecret,
	cookie: {
        "path": "/",
	    "maxAge": 24 * 60 * 60,
	    "secure": false,
	    "httpOnly": true
    },
	resave: false,
	store: new MongoStore({
		mongooseConnection: mongoose.connection,
		touchAfter: 24 * 60 * 60 // Check for TTL every 24 hours at minimum
	}),
	saveUninitialized: true
}));

interface IDocument {
    _id: mongoose.Types.ObjectId;
}

interface IUser extends IDocument {
    name: string;
    buildingSlug: string;
    room: string;
    photoURL: string;
    publicKey: string;
}
type IUserMongoose = IUser & mongoose.Document;
const User = mongoose.model<IUserMongoose>("User", new mongoose.Schema({
    name: {
        type: String,
        unique: true
    },
    buildingSlug: {
        type: String,
        unique: true
    },
    room: String,
    photoURL: String,
    publicKey: String
}));

interface IBuilding extends IDocument {
    name: string;
    nameSlug: string;
    description: string;
    pictureURL: string;
    location: string;

    access: {
        residents: {
            id: string;
        }[];
        guests: {
            id: string;
            expiration: Date;
        }[];
    };

    privateKey: string;
    publicKey: string;
    adminAccount: {
        hash: string;
        salt: string;
        sessionKeys: string[];
    }
}
type IBuildingMongoose = IBuilding & mongoose.Document;
const Building = mongoose.model<IBuildingMongoose>("Building", new mongoose.Schema({
    name: {
        type: String,
        unique: true
    },
    nameSlug: {
        type: String,
        unique: true
    },
    description: String,
    pictureURL: String,
    location: String,

    access: {
        residents: [{
            name: String,
            room: String,
            publicKey: String
        }],
        guests: [{
            name: String,
            publicKey: String,
            expiration: Date
        }]
    },

    privateKey: String,
    publicKey: String,
    adminAccount: {
        hash: String,
        salt: String,
        sessionKeys: [String]
    }
}));

async function setDefault() {
	if (await Building.find({ "name": "Hopkins" }).count() === 0) {
        let privateKey: Buffer = crypto.randomBytes(32);
        let publicKey: Buffer = secp256k1.publicKeyCreate(privateKey, true);
        const adminPasswordDefault: string = "admin";
        let salt = crypto.randomBytes(32);
        let hash = await getHashForPassword(adminPasswordDefault, salt);

        let buildingName = "Hopkins";
		await new Building({
            name: buildingName,
            nameSlug: slug(buildingName).toLowerCase(),
            description: "The best dormitory at Georgia Tech",
            pictureURL: "http://housing.gatech.edu/halls/Building%20Main%20Picture/094Main.jpg",
            location: "115 Bobby Dodd Way, Atlanta, GA 30313",

            access: {
                residents: [],
                guests: []
            },

            privateKey: privateKey.toString("hex"),
            publicKey: publicKey.toString("hex"),
            adminAccount: {
                hash: hash.toString("hex"),
                salt: salt.toString("hex"),
                sessionKeys: []
            }
		}).save();
        console.info(`Added default building and admin user account with password: ${adminPasswordDefault}`);
	}
}
setDefault();

///
/// Common functions
///
async function getHashForPassword(password: string, salt: Buffer) {
    return new Promise<Buffer>((resolve, reject) => {
        crypto.pbkdf2(password, salt, 100000, 256, "sha256", (err, hash) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(hash);
        });
    });
}

function readFileAsync(filename: string): Promise<string> {
    return new Promise<string>((resolve, reject) => {
        fs.readFile(filename, "utf8", (err, data) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(data);
        });
    });
}
async function loadBuilding(request: express.Request, response: express.Response, next: express.NextFunction) {
    let buildingSlug = request.params.building as string;
    try {
        let building = await Building.findOne({ "nameSlug": buildingSlug });
        if (!building) {
            response.status(400).json({
                "error": "Invalid building"
            });    
            return; 
        }
        response.locals.building = building;
        next();
    }
    catch (err) {
        console.error(err);
        response.status(500).json({
            "error": "An unexpected server error occurred"
        });
    }
}
async function isAdmin(request: express.Request, response: express.Response, next: express.NextFunction) {
    let sessionKey = request.session!.key;
    let buildingForAdmin = await Building.findOne({ "adminAccount.sessionKeys": sessionKey });
    if (!buildingForAdmin || buildingForAdmin.nameSlug !== (response.locals.building as IBuilding).nameSlug) {
        response.status(401).json({
            "error": "You are not authorized to access that endpoint"
        });
    }
    next();
}

///
/// API
///
let apiRouter = express.Router();

apiRouter.route("/addresident").post(isAdmin, async (request, response) => {

});

apiRouter.route("/access").post(async (request, response) => {
    
});

///
/// User facing routes
///
let mainRouter = express.Router();

app.route("/").get((request, response) => {
    response.send("Index page");
});
app.route("/login").get((request, response) => {
    response.send("Login page");
}).post(postParser, async (request, response) => {
    let buildingName = request.body.username as string;
    let building = await Building.findOne({ "name": buildingName });
    if (!building) {
        response.status(401).json({
            "error": "Invalid building"
        });
    }
    let password = request.body.password as string;
    if (!password) {
        response.status(400).json({
            "error": "Missing password"
        });
        return;
    }
    let salt = new Buffer(building.adminAccount.salt, "hex");
    let hashAttempt = await getHashForPassword(password, salt);
    if (hashAttempt.toString("hex") !== building.adminAccount.hash) {
        response.status(401).json({
            "error": "Invalid password"
        });
        return;
    }
    let sessionKey = crypto.randomBytes(32).toString("hex");
    request.session!.sessionKey = sessionKey;
    building.adminAccount.sessionKeys.push(sessionKey);
    try {
        await building.save();
        response.json({
            "success": true
        });
        // Client should redirect to /buildingSlug
    }
    catch (err) {
        console.error(err);
        response.status(500).json({
            "error": "An error occurred while logging in"
        });
    }
});

mainRouter.route("/").get((request, response) => {
    response.send("Hopkins");
});

mainRouter.use("/api", apiRouter);
app.use("/:building", loadBuilding, mainRouter);

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`GateKeeper server started on port ${PORT}`);
});