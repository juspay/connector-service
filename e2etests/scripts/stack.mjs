import { spawnSync } from "node:child_process";
import {
  mkdirSync, existsSync, readFileSync, writeFileSync, renameSync, rmSync,
} from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtime = resolve(root, ".runtime");
let checkout = process.env.HS_SOURCE_DIR
  ? resolve(process.env.HS_SOURCE_DIR)
  : resolve(runtime, "hyperswitch");
const override = resolve(runtime, "compose.e2e.yaml");
const versionsFile = resolve(runtime, "versions.json");
const image =
  process.env.HS_IMAGE ?? "docker.juspay.io/juspaydotin/hyperswitch-router:latest";
const action = process.argv[2];
if (!["up", "down", "prepare"].includes(action))
  throw new Error("Use stack.mjs up|down|prepare");
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0)
    throw new Error(`${command} exited ${result.status}`);
}
mkdirSync(runtime, { recursive: true });
if (action !== "down") {
  // Resolve configuration and migrations from the binary's own source revision.
  // Floating image and main tags are not guaranteed to describe the same build.
  let sourceRef = process.env.HS_REF;
  if (!process.env.HS_SOURCE_DIR) {
    if (!sourceRef) {
      if (action === "up") run("docker", ["pull", image]);
      const version = spawnSync("docker", ["run", "--rm", "--network", "none",
        "--entrypoint", "/local/bin/router", image, "--version"], { encoding: "utf8" });
      if (version.status !== 0) throw new Error("Cannot read HS image version; ensure Docker is running and the image is available");
      sourceRef = version.stdout.match(/-[0-9a-f]{7,40}-/)?.[0].slice(1, -1);
      if (!sourceRef) throw new Error("HS image does not report a source revision; set HS_REF or HS_SOURCE_DIR to its matching source");
    }
    const response = await fetch(`https://api.github.com/repos/juspay/hyperswitch/commits/${encodeURIComponent(sourceRef)}`, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Cannot resolve HS source revision (GitHub HTTP ${response.status}); retry or set HS_SOURCE_DIR`);
    const sourceCommit = (await response.json()).sha;
    if (!/^[0-9a-f]{40}$/.test(sourceCommit)) throw new Error("Invalid HS source revision");
    checkout = resolve(runtime, `hyperswitch-${sourceCommit}`);
    if (!existsSync(checkout)) {
      // Download only runtime assets. Publish the cache only after checkout succeeds.
      const pending = `${checkout}.partial`;
      rmSync(pending, { recursive: true, force: true });
      mkdirSync(pending, { recursive: true });
      run("git", ["init", "--quiet", pending]);
      run("git", ["-C", pending, "remote", "add", "origin", "https://github.com/juspay/hyperswitch.git"]);
      run("git", ["-C", pending, "fetch", "--depth", "1", "--filter=blob:none", "origin", sourceCommit]);
      run("git", ["-C", pending, "sparse-checkout", "set", "config", "migrations", "scripts", "files"]);
      run("git", ["-C", pending, "checkout", "--detach", "FETCH_HEAD"]);
      renameSync(pending, checkout);
    }
  }
  const config = resolve(runtime, "hs.toml");
  let contents = readFileSync(
    resolve(checkout, "config/docker_compose.toml"),
    "utf8",
  );
  // Support both existing and absent UCS sections without duplicate TOML tables.
  contents = contents.replace(
    /^\[grpc_client\.unified_connector_service\][\s\S]*?(?=^\[|$(?![\s\S]))/m,
    "",
  );
  contents +=
    "\n[grpc_client.unified_connector_service]\n" +
    `base_url = ${JSON.stringify(process.env.UCS_BASE_URL ?? "http://host.docker.internal:8000")}\n` +
    "connection_timeout = 10\nrequest_timeout = 60\n" +
    'ucs_only_connectors = "adyen,stripe,paypal,authorizedotnet,cybersource,checkout"\n';
  writeFileSync(config, contents);
  // Runtime migrations must not regenerate or patch the source checkout's schema.
  const dieselConfig = resolve(runtime, "diesel.toml");
  writeFileSync(dieselConfig, '[migrations_directory]\ndir = "/app/migrations"\n');
  const migrationCommand = [
    "set -eu",
    "apt-get update",
    "apt-get install -y curl xz-utils",
    "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/diesel-rs/diesel/releases/download/v2.3.5/diesel_cli-installer.sh -o /tmp/install-diesel.sh",
    "bash /tmp/install-diesel.sh",
    '/root/.cargo/bin/diesel migration run --database-url "$${DATABASE_URL}" --migration-dir /app/migrations --config-file /e2e-diesel.toml',
  ].join(" && ");
  writeFileSync(
    override,
    // Redis is accessed by its Compose service name; no host port is needed.
    // YAML's reset tag removes the port inherited from upstream Compose.
    "services:\n" +
      "  redis-standalone:\n    ports: !reset []\n" +
      "  migration_runner: " +
      JSON.stringify({
        command: ["bash", "-c", migrationCommand],
        volumes: [`${dieselConfig}:/e2e-diesel.toml:ro`],
        depends_on: { pg: { condition: "service_healthy" } },
      }) + "\n" +
      "  superposition-init: " +
      JSON.stringify({
        command: ["sh", "-c", "apk add --no-cache bash curl jq yq && bash /seed_superposition.sh"],
      }) + "\n" +
      "  hyperswitch-server: " +
      JSON.stringify({
        image,
        pull_policy: "missing",
        command: ["/local/bin/router", "-f", "/local/config/e2e.toml"],
        volumes: [`${config}:/local/config/e2e.toml:ro`],
        extra_hosts: ["host.docker.internal:host-gateway"],
        healthcheck: { start_period: "60s", retries: 30 },
      }) + "\n",
  );
  writeFileSync(
    versionsFile,
    JSON.stringify(
      {
        image,
        ucs: process.env.UCS_BASE_URL ?? "http://host.docker.internal:8000",
        hsSourceDir: checkout,
        hsCommit: spawnSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
          encoding: "utf8",
        }).stdout.trim(),
      },
      null,
      2,
    ),
  );
} else {
  if (!existsSync(override)) throw new Error("No E2E stack has been prepared");
  if (existsSync(versionsFile)) {
    checkout = JSON.parse(readFileSync(versionsFile, "utf8")).hsSourceDir ?? checkout;
  }
}
if (action === "prepare") {
  console.log(`Prepared ${override}`);
  process.exit(0);
}
const args = [
  "compose",
  "--project-name",
  "ucs-e2e",
  "--project-directory",
  checkout,
  "-f",
  resolve(checkout, "docker-compose.yml"),
  "-f",
  override,
];
// Compose starts the router and its declared dependencies only (no dashboard/SDK yet).
run("docker", [
  ...args,
  ...(action === "up"
    ? ["up", "-d", "--wait", "--wait-timeout", "600", "hyperswitch-server"]
    : ["down"]),
]);
