/**
 * ROUA for Google BigQuery (preview: generated from Google's documentation,
 * not yet run against a live project in CI).
 *
 * - A dedicated service account.
 * - roles/bigquery.dataViewer granted per table and view (BigQuery DCL), as
 *   they exist when setup runs; never on the dataset, so new tables stay
 *   closed. Tables with secret-looking columns are skipped.
 * - roles/bigquery.jobUser on the project with an IAM condition that ends at
 *   the expiry time: after that, the account cannot run queries.
 * - Optional: let one person or agent impersonate the account until expiry,
 *   so no long-lived key file ever exists.
 */
import { anyPatternRegex, engineMetadata, SECRET_REGEX, splitColumn } from "./common.js";
import type { AccountSpec, EnginePlan } from "./types.js";

const sh = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const bqLit = (s: string) => `'${s.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;

export const bqServiceAccountId = (name: string) => name.replace(/_/g, "-").slice(0, 30);

export function planBigQuery(spec: AccountSpec, now: Date): EnginePlan {
  const project = spec.database!;
  const sa = bqServiceAccountId(spec.name);
  const email = `${sa}@${project}.iam.gserviceaccount.com`;
  const member = `serviceAccount:${email}`;
  const exp = new Date(spec.expiresAt).toISOString();
  const meta = engineMetadata(spec, now);
  const datasets = spec.mode === "listed"
    ? [...new Set((spec.objects ?? []).map((o) => o.split(".")[0]!).filter((d) => !d.includes("*")))]
    : spec.schemas ?? [];
  const location = spec.location ?? "US";

  const allow = new Set(spec.columnsAllow ?? []);
  const deny = spec.columnsDeny ?? [];
  const colFull = "CONCAT(c.table_schema, '.', c.table_name, '.', c.column_name)";
  let hidden = `REGEXP_CONTAINS(LOWER(REGEXP_REPLACE(c.column_name, r'([a-z0-9])([A-Z])', r'\\1_\\2')), r'${SECRET_REGEX}')`;
  if (allow.size) hidden = `(${hidden} AND ${colFull} NOT IN (${[...allow].map(bqLit).join(", ")}))`;
  if (deny.length) hidden = `(${hidden} OR ${colFull} IN (${deny.map((d) => bqLit(splitColumn(d).join("."))).join(", ")}))`;
  const full = "CONCAT(t.table_schema, '.', t.table_name)";
  const filter = spec.mode === "listed"
    ? `REGEXP_CONTAINS(${full}, r'${anyPatternRegex(spec.objects ?? [])}')`
    : spec.exclude?.length ? `NOT REGEXP_CONTAINS(${full}, r'${anyPatternRegex(spec.exclude)}')` : "TRUE";
  const union = (view: "TABLES" | "COLUMNS", alias: string, cols: string) =>
    datasets.map((d) => `SELECT ${cols} FROM \`${project}.${d}.INFORMATION_SCHEMA.${view}\` ${alias}`).join("\n      UNION ALL ");

  const metadataGrants = [
    `-- grants.sql: structure only (L0) for ${email}: metadata of these datasets, no rows.`,
    "-- PREVIEW: generated from Google's documentation, not yet tested against a live project. Review before running.",
    ...datasets.map((d) => `GRANT \`roles/bigquery.metadataViewer\` ON SCHEMA \`${project}.${d}\` TO "${member}";`),
    "",
  ].join("\n");
  const grants = spec.mode === "metadata" ? metadataGrants : `-- grants.sql: table-level read for ${email}. Run by setup.sh (bq query), or paste into the BigQuery console.
-- PREVIEW: generated from Google's documentation, not yet tested against a live project. Review before running.
DECLARE granted INT64 DEFAULT 0;
DECLARE skipped ARRAY<STRING> DEFAULT [];
FOR t IN (
  SELECT tb.table_schema, tb.table_name,
         (SELECT COUNT(*) FROM (${union("COLUMNS", "c", "c.table_schema, c.table_name, c.column_name")}) c
           WHERE c.table_schema = tb.table_schema AND c.table_name = tb.table_name AND ${hidden}) AS hidden
    FROM (${union("TABLES", "t", "t.table_schema, t.table_name, t.table_type")}) tb
   WHERE ${filter.replace(/\bt\./g, "tb.")}
)
DO
  IF t.hidden = 0 THEN
    EXECUTE IMMEDIATE FORMAT("GRANT \`roles/bigquery.dataViewer\` ON TABLE \`%s.%s.%s\` TO \\"%s\\"", ${bqLit(project)}, t.table_schema, t.table_name, ${bqLit(member)});
    SET granted = granted + 1;
  ELSE
    SET skipped = ARRAY_CONCAT(skipped, [CONCAT(t.table_schema, '.', t.table_name)]);
  END IF;
END FOR;
IF granted = 0 THEN
  RAISE USING MESSAGE = 'ROUA: the scope matched no readable tables, so the account can read nothing. Check the project, datasets and listed tables (run discover.sql to see what exists).';
END IF;
SELECT granted AS tables_granted, skipped AS skipped_hidden_columns;
`;

  const setup = `#!/usr/bin/env bash
# setup.sh: create or update the ROUA service account for BigQuery.
# ROUA 0.1 (draft). Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
# PREVIEW: generated from Google's documentation, not yet tested against a live project. Review before running.
# Account: ${email}   profile: ${spec.profile}   expires: ${exp}
# Needs: gcloud and bq, logged in as someone who can manage IAM on ${project}.
set -euo pipefail
PROJECT=${sh(project)}
SA=${sh(sa)}
SA_EMAIL=${sh(email)}
EXPIRES=${sh(exp)}
# Optional: the person or agent who may use this account, e.g. user:you@example.com.
# They impersonate it until expiry, so no key file is ever created.
HOLDER="\${HOLDER:-}"

if ! gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SA" --project "$PROJECT" \\
    --display-name "ROUA ${spec.profile}: ${spec.name}" \\
    --description ${sh(meta.slice(0, 256))}
fi
gcloud iam service-accounts enable "$SA_EMAIL" --project "$PROJECT"

# Run queries until the expiry time, and not after.
gcloud projects add-iam-policy-binding "$PROJECT" \\
  --member "serviceAccount:$SA_EMAIL" --role roles/bigquery.jobUser \\
  --condition "expression=request.time < timestamp('$EXPIRES'),title=roua-expiry-${sa},description=ROUA expiry" \\
  --format none

if [ -n "$HOLDER" ]; then
  gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project "$PROJECT" \\
    --member "$HOLDER" --role roles/iam.serviceAccountTokenCreator \\
    --condition "expression=request.time < timestamp('$EXPIRES'),title=roua-holder-${sa},description=ROUA expiry" \\
    --format none
fi

# Read access per table, as tables exist now (grants.sql).
bq query --project_id "$PROJECT" --location ${sh(location)} --use_legacy_sql=false < grants.sql

echo "ROUA: $SA_EMAIL is ready. Use it with: gcloud config set auth/impersonate_service_account $SA_EMAIL"
`;

  const revoke = `#!/usr/bin/env bash
# revoke.sh: disable the ROUA service account now and remove its access.
set -euo pipefail
PROJECT=${sh(project)}
SA_EMAIL=${sh(email)}
gcloud iam service-accounts disable "$SA_EMAIL" --project "$PROJECT"
gcloud projects remove-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA_EMAIL" --role roles/bigquery.jobUser --all --format none || true
for k in $(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --managed-by user --format 'value(name)'); do
  gcloud iam service-accounts keys delete "$k" --iam-account "$SA_EMAIL" --quiet
done
echo "Disabled. Table grants remain but are unusable; drop.sh removes them with the account."
`;
  const drop = `#!/usr/bin/env bash
# drop.sh: delete the ROUA service account (its table grants go with it).
set -euo pipefail
gcloud iam service-accounts delete ${sh(email)} --project ${sh(project)} --quiet
`;
  return {
    engine: "bigquery",
    files: [
      { name: "setup.sh", run: "HOLDER=user:you@example.com bash setup.sh", content: setup },
      { name: "grants.sql", run: "run by setup.sh", content: grants },
      { name: "audit.sh", run: "bash audit.sh", content: auditBigQuery(email, project, location, now) },
      { name: "revoke.sh", run: "bash revoke.sh", content: revoke },
      { name: "drop.sh", run: "bash drop.sh", content: drop },
    ],
    warnings: [
      "Preview: generated from Google's documentation and not yet run against a live project. Review it, and please report anything that fails.",
      "Tables with secret-looking columns are skipped. Protect those columns with policy tags (column-level security) or an authorized view, then add the view.",
    ],
    manualSteps: [
      "Prefer impersonation (HOLDER=...) over key files: it ends at the expiry time with nothing to leak.",
      "Set a custom quota (query usage per user per day) so the account cannot run up a large bill.",
    ],
  };
}

/** Audit any service account's BigQuery and project access. */
export function auditBigQuery(email: string, project: string, location = "US", now: Date = new Date()): string {
  return `#!/usr/bin/env bash
# audit.sh: is ${email} actually read-only? Changes nothing.
# ROUA 0.1 audit for BigQuery (preview). Generated ${now.toISOString()} by the ROUA generator (kaizam.com).
set -uo pipefail
PROJECT=${sh(project)}
MEMBER=${sh(`serviceAccount:${email}`)}
fails=0
echo "Project-level roles (only roles/bigquery.jobUser, with an expiry condition, is expected):"
roles=$(gcloud projects get-iam-policy "$PROJECT" --flatten 'bindings[].members' \\
  --filter "bindings.members=$MEMBER" --format 'value(bindings.role,bindings.condition.expression)')
echo "$roles" | sed 's/^/  /'
if echo "$roles" | grep -v '^roles/bigquery.jobUser' | grep -q .; then echo "FAIL  R1  Extra project roles"; fails=$((fails+1)); else echo "PASS  R1  No extra project roles"; fi
if echo "$roles" | grep '^roles/bigquery.jobUser' | grep -q 'request.time'; then echo "PASS  E1  Query rights expire"; else echo "FAIL  E1  Query rights never expire"; fails=$((fails+1)); fi
echo "Object grants (only dataViewer or metadataViewer expected):"
bq query --project_id "$PROJECT" --location ${sh(location)} --use_legacy_sql=false --format pretty \\
  "SELECT object_schema, object_name, privilege_type,
          IF(privilege_type IN ('roles/bigquery.dataViewer', 'roles/bigquery.metadataViewer'), 'PASS', 'FAIL') AS status
     FROM \\\`region-${location.toLowerCase()}\\\`.INFORMATION_SCHEMA.OBJECT_PRIVILEGES
    WHERE grantee = '$MEMBER' ORDER BY 1, 2"
keys=$(gcloud iam service-accounts keys list --iam-account ${sh(email)} --managed-by user --format 'value(name)' 2>/dev/null | wc -l)
if [ "$keys" -gt 0 ]; then echo "WARN  K1  $keys user-managed key(s) exist: keys outlive the expiry. Prefer impersonation."; else echo "PASS  K1  No key files"; fi
[ "$fails" -eq 0 ] && echo "Project checks passed. Review the object grants above." || { echo "NOT READ-ONLY: $fails check(s) failed."; exit 1; }
`;
}
