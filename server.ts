import * as fs from "fs";
import * as crypto from "crypto";
const secp256k1 = require("secp256k1");

import * as express from "express";
import * as serveStatic from "serve-static";
import * as compression from "compression";

export let app = express();
app.use(compression());

///
/// Mongoose
///
import * as mongoose from "mongoose";
(<any>mongoose).Promise = global.Promise;
mongoose.connect("mongodb://localhost/gatekeeper");

interface IBuilding {
    _id: mongoose.Types.ObjectId;
    name: string;
    description: string;
    pictureURL: string;
    location: string;

    access: {
        residents: {
            name: string;
            room: string;
            publicKey: string;
        }[];
        guests: {
            name: string;
            publicKey: string;
            expiration: Date;
        }[];
    };

    privateKey: string;
    publicKey: string;
    adminAccount: {
        hash: string;
        salt: string;
    }
}
type IBuildingMongoose = IBuilding & mongoose.Document;
const Building = mongoose.model<IBuildingMongoose>("Building", new mongoose.Schema({
    name: {
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
        salt: String
    }
}));

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

async function setDefault() {
	if (await Building.find({ "name": "Hopkins" }).count() === 0) {
        let privateKey: Buffer = crypto.randomBytes(32);
        let publicKey: Buffer = secp256k1.publicKeyCreate(privateKey, true);
        const adminPasswordDefault: string = "admin";
        let salt = crypto.randomBytes(32);
        let hash = await getHashForPassword(adminPasswordDefault, salt);

		await new Building({
            name: "Hopkins",
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
                salt: salt.toString("hex")
            }
		}).save();
        console.info(`Added default building and admin user account with password: ${adminPasswordDefault}`);
	}
}
setDefault();

///
/// Common functions
///
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


app.route("/").get((request, response) => {
    response.send("GateKeeper");
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`GateKeeper server started on port ${PORT}`);
});