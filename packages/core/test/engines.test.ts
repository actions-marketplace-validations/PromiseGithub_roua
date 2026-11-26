import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ENGINES,
  ENGINE_INFO,
  auditScript,
  isSecretByLists,
  isSecretColumnName,
  mysqlNativeHash,
  planEngine,
  redisPasswordHash,
  sha1,
  sha256Crypt,
  sha512,
  sqlServerPasswordHash,
  validateSpec,
  type AccountSpec,
  type OtherEngine,
} from "@roua-dev/core";

const now = new Date("2026-11-24T00:00:00Z");
const PW = "Abcdefghijklmnop1234567890XYZabc";
const KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "A".repeat(300) + "IDAQAB";

function spec(engine: OtherEngine, over: Partial<AccountSpec> = {}): AccountSpec {
  const base: AccountSpec = {
    engine,
    name: "roua_agent_docs",
    profile: "agent",
    owner: "jane@example.com",
    purpose: "Docs agent",
    expiresAt: "2027-01-15T00:00:00Z",
    mode: "scope",
    database: engine === "bigquery" ? "my-project-123" : "appdb",
    schemas: ["app"],
    objects: engine === "redis" ? ["app:*"] : [],
    exclude: ["app.salaries"],
    columnsDeny: ["app.users.national_id"],
    password: PW,
    maxConnections: 5,
    statementTimeoutS: 30,
    warehouse: "ROUA_WH",
    publicKey: KEY,
    location: "US",
  };
  if (engine === "mongodb") base.exclude = ["salaries"];
  return { ...base, ...over };
}

const others = ENGINES.filter((e): e is OtherEngine => e !== "postgresql");

describe("hashes", () => {
  const enc = new TextEncoder();
  it("SHA-1 and SHA-512 match node:crypto", () => {
    for (const s of ["", "abc", "x".repeat(300), "pässwörd"]) {
      expect(Buffer.from(sha1(enc.encode(s))).toString("hex")).toBe(createHash("sha1").update(s).digest("hex"));
      expect(Buffer.from(sha512(enc.encode(s))).toString("hex")).toBe(createHash("sha512").update(s).digest("hex"));
    }
  });
  it("SHA-256-crypt matches OpenSSL and the published vectors", () => {
    expect(sha256Crypt("Hello world!", "saltstring")).toBe("5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");
    expect(sha256Crypt("Hello world!", "saltstringsaltstring", 10000)).toBe("3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");
    expect(sha256Crypt("pw", "abcdefghij0123456789")).toBe("3I6hNPImAlFiuAr64X4SnkKZkNm4V53c4sivmGoKoL8");
  });
  it("engine verifiers have the right shape", () => {
    expect(mysqlNativeHash("password")).toBe("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19");
    expect(redisPasswordHash("abc")).toBe(createHash("sha256").update("abc").digest("hex"));
    const salt = new Uint8Array([1, 2, 3, 4]);
    const expected = createHash("sha512").update(Buffer.concat([Buffer.from("pw", "utf16le"), Buffer.from(salt)])).digest("hex").toUpperCase();
    expect(sqlServerPasswordHash("pw", salt)).toBe("0x020001020304" + expected);
  });
});

describe("secret detector lists", () => {
  it("are equivalent to the regex detector", () => {
    const names = [
      "password", "user_password", "passwordHash", "pwd", "user_pwd", "pin", "pin_code", "spinner", "pinned", "mfa_secret",
      "otp", "otpauth_url", "totp", "salt", "salted", "cvv", "cvv2", "pan", "company", "panel", "passphrase", "apiKey", "api_key",
      "privateKey", "seed", "seeded", "nonce", "token", "tokens_used", "refreshToken", "credential", "encryptionKey", "sessionKey",
      "accessKey", "signing_key", "masterKey", "cardNumber", "card_num", "webhookSig", "signatureKey", "recoveryCodes", "backup_code",
      "passHash", "hashedPassword", "email", "name", "created_at", "id", "secretary", "keyboard", "pandas", "PIN", "UserPIN", "userPin",
    ];
    for (const n of names) expect(isSecretByLists(n), n).toBe(isSecretColumnName(n));
  });
});

describe("every engine", () => {
  for (const e of others) {
    describe(ENGINE_INFO[e].name, () => {
      const plan = planEngine(spec(e), now);
      const all = plan.files.map((f) => f.content).join("\n");

      it("produces setup, audit and revoke", () => {
        const names = plan.files.map((f) => f.name);
        expect(names.some((n) => n.startsWith("setup"))).toBe(true);
        expect(names.some((n) => n.startsWith("audit"))).toBe(true);
        expect(names.some((n) => n.startsWith("revoke"))).toBe(true);
      });

      it("handles the password as the engine allows", () => {
        const kind = ENGINE_INFO[e].fields.password;
        if (kind === "verifier") expect(all).not.toContain(PW);
        if (kind === "plaintext") expect(all).toContain(PW);
        if (kind === "keypair" || kind === "none") expect(all).not.toContain(PW);
      });

      it("records the expiry", () => {
        expect(all).toMatch(/2027-01-15/);
      });

      it("never grants database-wide or future read", () => {
        const grants = all.split("\n").filter((l) => /\bGRANT\s+(SELECT|READ|USAGE|ROLE|CONNECT|CREATE|`roles)|createRole|roles:/.test(l) && !/^\s*(--|\/\/|#)/.test(l));
        if (e !== "redis") expect(grants.length).toBeGreaterThan(0);
        for (const l of grants) expect(l).not.toMatch(/db_datareader|readAnyDatabase|FUTURE|(SELECT|READ)[^;]*ON SCHEMA|ON ALL |ON \*|ON `?\w+`?\.\* TO|ANY TABLE|ON DATABASE::/i);
        expect(all).not.toMatch(/db_datareader|readAnyDatabase|ON FUTURE/i);
      });

      it("rejects injection in names and text", () => {
        expect(validateSpec(spec(e, { name: "x'; DROP" }), now).errors.length).toBeGreaterThan(0);
        expect(validateSpec(spec(e, { owner: "a'b" }), now).errors.length).toBeGreaterThan(0);
        expect(validateSpec(spec(e, { purpose: "x\\y" }), now).errors.length).toBeGreaterThan(0);
        if (e !== "redis") expect(validateSpec(spec(e, { exclude: ["a.b'c"] }), now).errors.length).toBeGreaterThan(0);
      });

      it("enforces the profile's maximum lifetime", () => {
        expect(validateSpec(spec(e, { expiresAt: "2028-01-01T00:00:00Z" }), now).errors.join()).toMatch(/at most 90 days/);
      });

      it("audits an existing account", () => {
        const a = auditScript({ engine: e, name: "legacy_ro", database: e === "bigquery" ? "my-project-123" : "appdb" }, now);
        expect(a.content).toMatch(/PASS/);
      });
    });
  }
});

describe("MySQL and MariaDB", () => {
  it("grant only SELECT, per table, through information_schema", () => {
    for (const e of ["mysql", "mariadb"] as const) {
      const setup = planEngine(spec(e), now).files[0]!.content;
      const grants = [...setup.matchAll(/'GRANT (\w+)/g)].map((m) => m[1]);
      expect(grants.length).toBeGreaterThan(0);
      expect(new Set(grants)).toEqual(new Set(["SELECT"]));
      expect(setup).toContain("REVOKE ALL PRIVILEGES, GRANT OPTION");
      expect(setup).toContain("CREATE EVENT roua_admin.`roua_expire_roua_agent_docs`");
    }
  });
  it("keeps SIGNAL messages within MySQL's 128-character limit", () => {
    for (const e of ["mysql", "mariadb"] as const) {
      const setup = planEngine(spec(e), now).files[0]!.content;
      const messages = [...setup.matchAll(/MESSAGE_TEXT = '([^']*)'/g)].map((m) => m[1]!);
      expect(messages.length).toBeGreaterThan(0);
      for (const m of messages) expect(m.length, m).toBeLessThanOrEqual(128);
    }
  });

  it("uses caching_sha2 on MySQL and a native hash on MariaDB", () => {
    expect(planEngine(spec("mysql"), now).files[0]!.content).toMatch(/caching_sha2_password AS '\$A\$005\$[A-Za-z0-9]{20}[./A-Za-z0-9]{43}'/);
    expect(planEngine(spec("mariadb"), now).files[0]!.content).toContain(`IDENTIFIED BY PASSWORD '${mysqlNativeHash(PW)}'`);
  });
});

describe("SQL Server", () => {
  it("denies writes database-wide and hashes the password", () => {
    const setup = planEngine(spec("sqlserver"), now).files[0]!.content;
    expect(setup).toMatch(/DENY INSERT, UPDATE, DELETE, EXECUTE, ALTER/);
    expect(setup).toMatch(/WITH PASSWORD = 0x0200[0-9A-F]{136} HASHED/);
  });
  it("contained users carry a plaintext password and no server objects", () => {
    const plan = planEngine(spec("sqlserver", { contained: true }), now);
    expect(plan.files[0]!.content).toContain(`CREATE USER [roua_agent_docs] WITH PASSWORD = N'${PW}'`);
    expect(plan.files[0]!.content).not.toContain("CREATE LOGIN");
  });
});

describe("Oracle", () => {
  it("grants READ, never SELECT, and schedules a lock", () => {
    const setup = planEngine(spec("oracle"), now).files[0]!.content;
    expect(setup).toContain(`'GRANT READ ON "'`);
    expect(setup).not.toMatch(/GRANT SELECT/);
    expect(setup).toContain("DBMS_SCHEDULER.CREATE_JOB");
  });
});

describe("Redis", () => {
  it("allows read commands on the listed patterns only", () => {
    const setup = planEngine(spec("redis"), now).files[0]!.content;
    expect(setup).toMatch(/ACL SETUSER roua_agent_docs on #[0-9a-f]{64} %R~app:\* resetchannels -@all \+@read \+@connection -@write -@dangerous -@admin -@scripting -@pubsub/);
  });
  it("requires at least one key pattern", () => {
    expect(validateSpec(spec("redis", { objects: [] }), now).errors.join()).toMatch(/Key patterns/);
  });
});

describe("Snowflake and BigQuery", () => {
  it("Snowflake uses key-pair login, no secondary roles and DAYS_TO_EXPIRY", () => {
    const setup = planEngine(spec("snowflake"), now).files[0]!.content;
    expect(setup).toContain("TYPE = SERVICE");
    expect(setup).toContain("DEFAULT_SECONDARY_ROLES = ()");
    expect(setup).toMatch(/DAYS_TO_EXPIRY = 52/);
    expect(validateSpec(spec("snowflake", { publicKey: "nope" }), now).errors.join()).toMatch(/public key/);
  });
  it("BigQuery query rights expire through an IAM condition", () => {
    const setup = planEngine(spec("bigquery"), now).files[0]!.content;
    expect(setup).toContain("request.time < timestamp('$EXPIRES')");
    expect(setup).toContain("roles/bigquery.jobUser");
  });
});
