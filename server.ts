import * as path from "path";
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
const postParser = bodyParser.urlencoded({
    extended: false
});
import * as Handlebars from "handlebars";

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
    location: {
        address: string;
        latitude: number;
        longitude: number;   
    };

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
    location: {
        address: String,
        latitude: Number,
        longitude: Number
    },

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
            location: {
                address: "115 Bobby Dodd Way, Atlanta, GA 30313",
                latitude: 33.774081,
                longitude: -84.391283
            },

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
    let {sessionKey} = request.session!;
    let buildingForAdmin = await Building.findOne({ "adminAccount.sessionKeys": sessionKey });
    if (!buildingForAdmin || buildingForAdmin.nameSlug !== (response.locals.building as IBuilding).nameSlug) {
        response.status(401).json({
            "error": "You are not authorized to access that endpoint"
        });
        return;
    }
    next();
}

///
/// API
///
let apiRouter = express.Router();

apiRouter.route("/add_user_to_building").post(isAdmin, postParser, async (request, response) => {
    let building = response.locals.building as IBuildingMongoose;
    let {name, room}: {
        name: string | undefined;
        room: string | undefined
    } = request.body;
    if (!name || !room) {
        response.status(400).json({
            "error": "Missing user's name or room number"
        });
        return;
    }
    let user = await User.findOne({ name });
    if (!user) {
        response.status(400).json({
            "error": "Invalid user name"
        });
        return;
    }
    user.room = room;
    user.buildingSlug = building.nameSlug;
    try {
        building.access.residents.push({
            "id": user._id.toString()
        });
        await building.save();
        await user.save();
        response.json({
            "success": true
        });
    }
    catch (err) {
        console.error(err);
        response.status(500).json({
            "error": "An error occurred while adding user to building"
        });
    }
});

apiRouter.route("/tap").post(postParser, async (request, response) => {

});

///
/// User facing routes
///
let mainRouter = express.Router();
/*let [
	indexTemplate,
	dashboardTemplate,
	loginTemplate,
    signupTemplate
] = [
	"index.html",
	"dashboard.html",
	"login.html",
    "signup.html"
].map(file => {
	let data = fs.readFileSync(path.resolve(__dirname, "client", file), "utf8");
	return Handlebars.compile(data);
});*/

app.route("/").get(async (request, response) => {
    let indexTemplate = Handlebars.compile(await readFileAsync(path.resolve(__dirname, "client/index.html")));
    response.send(indexTemplate({}));
});
app.route("/login").get(async (request, response) => {
    let loginTemplate = Handlebars.compile(await readFileAsync(path.resolve(__dirname, "client/login.html")));
    response.send(loginTemplate({}));
}).post(postParser, async (request, response) => {
    let buildingName = request.body.building as string;
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
    request.session!.save(() => {});
    building.adminAccount.sessionKeys.push(sessionKey);
    try {
        await building.save();
        response.json({
            "success": true,
            "redirect": "/" + building.nameSlug
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
app.route("/signup").get(async (request, response) => {
    let signupTemplate = Handlebars.compile(await readFileAsync(path.resolve(__dirname, "client/signup.html")));
    response.send(signupTemplate({}));
}).post(postParser, async (request, response) => {
    // Create a new building + admin account
    let {building, description, password, pictureURL, address, latitude, longitude}: {
        building: string | undefined;
        description: string | undefined;
        password: string | undefined;
        pictureURL: string | undefined;
        address: string | undefined;
        latitude: string | undefined;
        longitude: string | undefined;
    } = request.body;
    if (!building || !description || !password || !pictureURL || !address || !latitude || !longitude) {
        response.status(400).json({
            "error": "Missing building, description, password, picture URL, latitude, or longitude"
        });
        return;
    }

    let privateKey: Buffer = crypto.randomBytes(32);
    let publicKey: Buffer = secp256k1.publicKeyCreate(privateKey, true);
    let salt = crypto.randomBytes(32);
    let hash = await getHashForPassword(password, salt);
    try {
        await new Building({
            name: building,
            nameSlug: slug(building).toLowerCase(),
            description: description,
            pictureURL: pictureURL,
            location: {
                address: address,
                latitude: parseFloat(latitude),
                longitude: parseFloat(longitude)
            },

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
        response.json({
            "success": true
        });
    }
    catch (err) {
        console.error(err);
        response.status(500).json({
            "error": "An error occurred while saving the new building and associated admin account"
        });
    }
});
app.route("/logout").all(async (request, response) => {
    let sessionKey = request.session!.sessionKey;
    request.session!.sessionKey = null;
    request.session!.save(() => {});
    await Building.update({ "adminAccount.sessionKeys": sessionKey }, { $pull: { "adminAcount.sessionKeys": sessionKey }});
    response.redirect("/");
});
app.route("/upload").post(postParser, async (request, response) => {
    let {name, pictureURL, publicKey, signature}: {
        name: string | undefined;
        pictureURL: string | undefined;
        publicKey: string | undefined;
        signature: string | undefined;
    } = request.body;
    if (!name || !pictureURL || !publicKey || !signature) {
        response.json({
            "error": "Missing name, picture URL, public key, or payload signature"
        });
        return;
    }
    if (!secp256k1.publicKeyVerify(new Buffer(publicKey, "hex"))) {
        response.json({
            "error": "Invalid public key"
        });
        return;
    }
    let signatureParsed = secp256k1.signatureImport(new Buffer(signature, "hex"));
    let signatureValid = secp256k1.verify(crypto.createHash("sha256").update(new Buffer(name + pictureURL + publicKey, "utf8")).digest(), signatureParsed, new Buffer(publicKey, "hex"));
    if (!signatureValid) {
        response.json({
            "error": "Invalid signature"
        });
        return;
    }
    try {
        await new User({
            name,
            pictureURL,
            publicKey
        }).save();
        response.json({
            "success": true
        });
    }
    catch (err) {
        console.error(err);
        response.status(500).json({
            "error": "An error occurred while saving new user"
        });
    }
});
app.route("/buildings").get(async (request, response) => {
    response.json((await Building.find()).map(building => {
        return {
            name: building.name,
            nameSlug: building.nameSlug,
            description: building.description,
            pictureURL: building.pictureURL,
            location: building.location
        };
    }));
});

mainRouter.route("/").get(isAdmin, async (request, response) => {
    let building = response.locals.building as IBuilding;
    let dashboardTemplate = Handlebars.compile(await readFileAsync(path.resolve(__dirname, "client/dashboard.html")));
    response.send(dashboardTemplate({
        name: building.name,
        residents: await User.find({ "buildingSlug": building.nameSlug })
    }));
});

mainRouter.use("/api", apiRouter);
app.use("/css", serveStatic("client/css"));
app.use("/:building", loadBuilding, mainRouter);

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`GateKeeper server started on port ${PORT}`);
});