import http from "node:http";
import handler from "../api/agent.js";

const PORT = Number(process.env.PORT || 8787);

http
  .createServer(async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      console.error("unhandled", err);
      res.statusCode = 500;
      res.end(JSON.stringify({ ok: false, error: "internal" }));
    }
  })
  .listen(PORT, () => console.log(`agent listening on http://127.0.0.1:${PORT}/agent`));
