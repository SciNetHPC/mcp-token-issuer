import express from "express";
import session from "express-session";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { config } from "./config";
import { log } from "./log";
import { registerRoutes } from "./routes";
import { startDisableSweep } from "./disable";
import { initStore } from "./tokens";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// A cluster-gated service without a directory would be hidden on every
// request, which looks like a permissions bug rather than a configuration
// error.  Fail at startup instead.
const gatedServices = config.services.filter((service) => service.slurmCluster);
if (gatedServices.length > 0 && !config.ldap.enabled) {
    log.error(
        "LDAP_URL is required because the service list contains cluster-gated entries",
        { services: gatedServices.map((service) => service.id) },
    );
    process.exit(1);
}

await initStore();

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(
    session({
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: config.production,
            maxAge: 8 * 60 * 60 * 1000,
        },
        // Single in-process alloc: the default MemoryStore is fine, and the
        // OIDC pending-state map in oidc.ts already tolerates restarts.
    }),
);

// On the first visit in a browser session, try passive SSO before showing
// the signed-out page.  The IdP session is often already established by the
// chatbot, so a `prompt=none` round trip returns without any click.  If it
// fails, the callback suppresses another attempt and the normal page is shown.
app.get("/", (req, res, next) => {
    if (req.session.user || req.session.silentAttempted || !config.oidc.enabled) {
        next();
        return;
    }
    req.session.silentAttempted = true;
    res.redirect("/login?silent=1");
});

app.use(express.static(path.join(__dirname, "public")));
registerRoutes(app);

app.listen(config.port, () => {
    log.log(`token-issuer listening on http://0.0.0.0:${config.port}`);
    if (!config.oidc.enabled) {
        log.warn("OIDC is not configured (OIDC_CLIENT_ID/SECRET/REDIRECT_URI); /login is disabled");
    }
    if (!config.ldap.enabled) {
        log.log("LDAP_URL is not configured; no cluster-gated services are configured");
    }
    startDisableSweep();
});
