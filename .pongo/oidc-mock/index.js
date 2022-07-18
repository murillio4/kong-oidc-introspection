import { OAuth2Server } from 'oauth2-mock-server';
import bodyParser from 'body-parser';


const server = new OAuth2Server();

await server.issuer.keys.generateRSA();

await server.start(8080);
server.issuer.url = "http://oidc-mock:8080"


const app = server.service.requestHandler;
app.use(bodyParser.urlencoded({ extended: false }));

app.post("/generate-token", (req, res) => {
    res.set({
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
    });

    const ttl = req.body.ttl != undefined ? parseInt(req.body.ttl) : 3600;

    const xfn = (_header, payload) => {
        Object.assign(payload, {
          sub: "John Doe",
          amr: ['pwd'],
          aud: req.body.aud ?? "no-aud",
          scope: req.body.scope,
        });
    }

    res.send(server.issuer.buildToken(true, undefined, xfn, ttl));
});

app.get("/headers", (req, res) => {
    res.send(JSON.stringify(req.headers));
});

app.get("/healthcheck", (req, res) => {
    res.send();
});


process.once('SIGINT', async () => {
    await server.stop();
    console.log('OAuth 2 server has been stopped.');
});