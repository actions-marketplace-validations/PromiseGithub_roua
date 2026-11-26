/**
 * ROUA for Redis 6.2+ and Valkey 7+.
 *
 * - ACL user: read commands only, on your key patterns only (%R~ on Redis 7+,
 *   so even a mistaken write command could not touch those keys), no pub/sub
 *   channels, and no @dangerous, @admin or @scripting commands (no KEYS,
 *   CONFIG, MONITOR, DEBUG, EVAL).
 * - Only the SHA-256 of the password is sent (#hash).
 * - Redis has no expiry for users: schedule revoke.redis.
 */
import { redisPasswordHash } from "../hashes.js";
import { header } from "./common.js";
import { scheduleTemplates } from "./schedule.js";
import type { AccountSpec, EnginePlan } from "./types.js";

export function redisAclRules(spec: AccountSpec): string {
  const keys = (spec.objects ?? []).map((p) => (spec.redis7 === false ? `~${p}` : `%R~${p}`));
  return [
    "on",
    `#${redisPasswordHash(spec.password ?? "")}`,
    ...keys,
    "resetchannels",
    "-@all",
    "+@read",
    "+@connection",
    "-@write",
    "-@dangerous",
    "-@admin",
    "-@scripting",
    "-@pubsub",
  ].join(" ");
}

export function planRedis(spec: AccountSpec, now: Date): EnginePlan {
  const u = spec.name;
  // redis-cli has no comment syntax: the header is printed with ECHO instead.
  const echo = (title: string, extra: string[] = []) =>
    [title, ...header("", spec, now, "").split("\n").slice(1).filter(Boolean), ...extra]
      .map((l) => `ECHO "${l.replace(/["\\]/g, "'").trim()}"`)
      .join("\n") + "\n";
  const setup = `${echo("ROUA setup.redis: create or update the ROUA ACL user. Run: redis-cli -h HOST --user admin --askpass < setup.redis", [
    "Only the SHA-256 of the password is in this file.",
    "Rules: read commands only, on the listed key patterns only; no channels; no dangerous, admin or scripting commands.",
  ])}ACL SETUSER ${u} reset
ACL SETUSER ${u} ${redisAclRules(spec)}
ACL GETUSER ${u}
ECHO "Saving the ACL. ACL SAVE fails if the server has no aclfile: then run CONFIG REWRITE if users live in redis.conf."
ACL SAVE
`;
  const revoke = `${echo("ROUA revoke.redis: disable the user now and disconnect it.")}ACL SETUSER ${u} off resetpass -@all
CLIENT KILL USER ${u}
ACL SAVE
`;
  const drop = `${echo("ROUA drop.redis: delete the user (run revoke.redis first).")}ACL DELUSER ${u}
ACL SAVE
`;
  const sample = (spec.objects?.[0] ?? "roua:*").replace(/\*/g, "x").replace(/[{}]/g, "");
  return {
    engine: "redis",
    files: [
      { name: "setup.redis", run: "redis-cli -h HOST --user admin --askpass < setup.redis", content: setup },
      { name: "audit.sh", run: "REDISCLI_AUTH=... REDIS_CLI='redis-cli -h HOST --user admin' sh audit.sh", content: auditRedis(u, now, sample, spec.redis7 !== false) },
      { name: "revoke.redis", run: "redis-cli -h HOST --user admin --askpass < revoke.redis", content: revoke },
      { name: "drop.redis", run: "redis-cli -h HOST --user admin --askpass < drop.redis", content: drop },
      { name: "schedule-revoke.md", run: "pick one scheduler and set it up", content: scheduleTemplates(spec, "revoke.redis", 'redis-cli -u "$REDIS_ADMIN_URL" < revoke.redis') },
    ],
    warnings: spec.redis7 === false ? ["Redis 6.2 has no read-only key permissions (%R~); write commands are still blocked by command category."] : [],
    manualSteps: [
      `Redis users never expire on their own. Schedule revoke.redis for ${new Date(spec.expiresAt).toISOString()}, for example with cron or a CI schedule.`,
      "Key patterns apply to every logical database (SELECT 0-15).",
      "Managed services: Amazon ElastiCache and MemoryDB use RBAC user groups with the same ACL rule string; Azure Cache for Redis uses data access policies with these command categories.",
    ],
  };
}

/** Audit any Redis/Valkey ACL user with redis-cli. */
export function auditRedis(user: string, now: Date = new Date(), sampleKey = "roua:probe", redis7 = true): string {
  return `#!/bin/sh
# audit.sh: is ${user} actually read-only? Safe to run anytime; changes nothing.
# ROUA 0.1 audit for Redis/Valkey. Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
# REDISCLI_AUTH='admin-password' REDIS_CLI='redis-cli -h HOST --user admin' sh audit.sh
# Every line should say PASS.
set -f
CLI=\${REDIS_CLI:-redis-cli}
U='${user}'
fails=0
ok()   { printf 'PASS  %-4s%s\\n' "$1" "$2"; }
bad()  { printf 'FAIL  %-4s%s\\n          %s\\n' "$1" "$2" "$3"; fails=$((fails+1)); }
warn() { printf 'WARN  %-4s%s\\n          %s\\n' "$1" "$2" "$3"; }

info=$($CLI ACL GETUSER "$U" 2>&1)
if [ -z "$info" ] || echo "$info" | grep -qi "nil\\|ERR"; then bad A1 "User exists" "$info"; exit 1; fi
rules=$($CLI ACL LIST | grep "^user $U ")
echo "$rules" | grep -q " on " && ok A1 "User exists and is enabled" || warn A1 "User exists and is enabled" "User is off"
echo "$rules" | grep -q "nopass" && bad P1 "Has a password" "nopass: anyone can log in as $U" || ok P1 "Has a password"
echo "$rules" | grep -Eq '(^| )(\\+@all|allcommands|\\+@write|\\+@admin|\\+@dangerous)( |$)' && bad R1 "No write, admin or dangerous command categories" "$rules" || ok R1 "No write, admin or dangerous command categories"
echo "$rules" | grep -Eq '(^| )(~\\*|allkeys|%RW~\\*|%W~)' && bad K1 "Keys limited to patterns, read-only" "$rules" || ok K1 "Keys limited to patterns, read-only"
echo "$rules" | grep -Eq '(^| )(&\\*|allchannels)( |$)' && bad C1 "No pub/sub channels" "$rules" || ok C1 "No pub/sub channels"
${redis7 ? `for cmd in "SET ${sampleKey} roua" "DEL ${sampleKey}" "FLUSHALL" "CONFIG SET maxmemory 1" "KEYS *" "EVAL return 1 0" "MONITOR" "PUBLISH roua x"; do
  r=$($CLI ACL DRYRUN "$U" $cmd 2>&1)
  if [ "$r" = "OK" ]; then bad W1 "Refuses: $cmd" "ACL DRYRUN allowed it"; else ok W1 "Refuses: $cmd"; fi
done
r=$($CLI ACL DRYRUN "$U" GET ${sampleKey} 2>&1)
[ "$r" = "OK" ] && ok W2 "Can read ${sampleKey}" || warn W2 "Can read ${sampleKey}" "$r"` : `echo "INFO  W1  Redis 6.2 has no ACL DRYRUN: log in as $U and try a SET to confirm it fails."`}
d=$($CLI ACL LIST | grep "^user default ")
echo "$d" | grep -q " on " && echo "$d" | grep -q "nopass" && bad Z1 "The default user is not open" "default user is on with nopass: anyone can connect with full access" || ok Z1 "The default user is not open"
echo "INFO  E1  Redis users never expire on their own: make sure revoke.redis is scheduled."
[ "$fails" -eq 0 ] && echo "READ-ONLY: every check passed." || { echo "NOT READ-ONLY: $fails check(s) failed."; exit 1; }
`;
}
