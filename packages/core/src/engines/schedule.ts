/**
 * Ready-made schedules for engines without built-in account expiry (MongoDB,
 * Redis): cron, systemd, Kubernetes, GitHub Actions and Windows Task
 * Scheduler, each set to the account's expiry time in UTC.
 */
import { ENGINE_INFO, type AccountSpec } from "./types.js";

const p = (n: number) => String(n).padStart(2, "0");
const fence = "```";

export function scheduleTemplates(spec: AccountSpec, revokeFile: string, revokeCommand: string): string {
  const d = new Date(spec.expiresAt);
  const Y = d.getUTCFullYear();
  const M = d.getUTCMonth() + 1;
  const D = d.getUTCDate();
  const h = d.getUTCHours();
  const m = d.getUTCMinutes();
  const cron = `${m} ${h} ${D} ${M} *`;
  const name = spec.name.replace(/_/g, "-");
  const shQuoted = `'${revokeCommand.replace(/'/g, `'\\''`)}'`;
  const image = spec.engine === "redis" ? "redis:7" : "mongo:8";
  return [
    `# Schedule the revoke for ${spec.name}`,
    "",
    `${ENGINE_INFO[spec.engine].name} cannot expire accounts on its own. Schedule \`${revokeFile}\` for **${d.toISOString()}** with a scheduler you already run. All times below are UTC. If the schedule is missed, the audit fails once the expiry has passed.`,
    "",
    "Keep the administrator credentials the command needs in the scheduler's secret store, never in this file.",
    "",
    "## cron (Linux, macOS)",
    "",
    `Runs on ${Y}-${p(M)}-${p(D)} at ${p(h)}:${p(m)} (the machine's clock must be UTC; adjust otherwise). Delete the line once it has run.`,
    "",
    `${fence}cron`,
    `${cron} ${revokeCommand}`,
    fence,
    "",
    "## systemd timer",
    "",
    `${fence}ini`,
    `# /etc/systemd/system/roua-revoke-${name}.service`,
    "[Service]",
    "Type=oneshot",
    `ExecStart=/bin/sh -c ${shQuoted}`,
    "",
    `# /etc/systemd/system/roua-revoke-${name}.timer`,
    "[Timer]",
    `OnCalendar=${Y}-${p(M)}-${p(D)} ${p(h)}:${p(m)}:00 UTC`,
    "Persistent=true",
    "[Install]",
    "WantedBy=timers.target",
    fence,
    "",
    `Then run \`systemctl enable --now roua-revoke-${name}.timer\`.`,
    "",
    "## Kubernetes CronJob",
    "",
    `${fence}yaml`,
    "apiVersion: batch/v1",
    "kind: CronJob",
    "metadata:",
    `  name: roua-revoke-${name}`,
    "spec:",
    `  schedule: "${cron}"`,
    '  timeZone: "Etc/UTC"',
    "  concurrencyPolicy: Forbid",
    "  jobTemplate:",
    "    spec:",
    "      template:",
    "        spec:",
    "          restartPolicy: OnFailure",
    "          containers:",
    "            - name: revoke",
    `              image: ${image}`,
    `              command: ["/bin/sh", "-c", ${JSON.stringify(revokeCommand)}]`,
    `              # Mount ${revokeFile} from a ConfigMap and the admin credentials from a Secret.`,
    fence,
    "",
    "Delete the CronJob once it has run.",
    "",
    "## GitHub Actions",
    "",
    `${fence}yaml`,
    `name: Revoke ${spec.name}`,
    "on:",
    "  schedule:",
    `    - cron: "${cron}"`,
    "jobs:",
    "  revoke:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    `      - run: ${revokeCommand}`,
    fence,
    "",
    "Scheduled workflows can start a few minutes late. Keep the administrator credentials in repository secrets.",
    "",
    "## Windows Task Scheduler",
    "",
    `${fence}powershell`,
    `schtasks /Create /TN "ROUA revoke ${spec.name}" /SC ONCE /SD ${p(M)}/${p(D)}/${Y} /ST ${p(h)}:${p(m)} /TR "cmd /c ${revokeCommand.replace(/"/g, '\\"')}"`,
    fence,
    "",
    "/SD and /ST use the machine's local time and date format: convert from UTC.",
    "",
  ].join("\n");
}
