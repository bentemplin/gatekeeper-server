import * as express from "express";
import * as serveStatic from "serve-static";
import * as compression from "compression";

export let app = express();
app.use(compression());

app.route("/").get((request, response) => {
    response.send("GateKeeper");
});

const PORT = 3000;
app.listen(PORT, () => {
	console.log(`GateKeeper server started on port ${PORT}`);
});