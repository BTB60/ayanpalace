// Local demo entrypoint: runs server.js against an in-memory PostgreSQL (pg-mem),
// so the project works without a real database. Data resets on restart.
// Usage: npm run demo  (or: node dev-server.js)
require("dotenv").config();
const path = require("path");

const MULTI_STATEMENT_RE = /CREATE TABLE|CREATE INDEX/i;

async function main() {
  const { newDb } = require("pg-mem");
  const db = await newDb();
  const { Pool } = db.adapters.createPg();

  // server.js applies db/schema.sql as a single query; pg-mem needs one statement per call.
  class DemoPool extends Pool {
    query(sql, params) {
      if (typeof sql === "string" && MULTI_STATEMENT_RE.test(sql)) {
        const statements = sql.split(";").map((s) => s.trim()).filter(Boolean);
        return statements.reduce(
          (chain, stmt) => chain.then(() => super.query(stmt)),
          Promise.resolve()
        ).then(() => ({ rows: [], rowCount: 0 }));
      }
      return super.query(sql, params);
    }
  }

  // Make server.js pick up the in-memory Pool when it requires("pg").
  const pg = require("pg");
  pg.Pool = DemoPool;
  require(path.join(__dirname, "server.js"));

  console.log("Demo mode: in-memory PostgreSQL (data resets on restart).");
  console.log(`Admin login -> username: ${process.env.ADMIN_USERNAME || "admin"}, password: ${process.env.ADMIN_PASSWORD}`);
}

main().catch((e) => { console.error("Demo startup error:", e); process.exit(1); });
