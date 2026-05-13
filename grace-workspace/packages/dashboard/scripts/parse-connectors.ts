#!/usr/bin/env tsx
/**
 * Parse all_connector.md into structured JSON for dashboard consumption
 * Run during build: `tsx scripts/parse-connectors.ts`
 */
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface ConnectorData {
  name: string;
  filePath: string;
  paymentMethods: Array<{
    category: string;
    method: string;
    status: "supported" | "not_supported" | "not_implemented" | "error";
  }>;
  stats: {
    total: number;
    supported: number;
    notImplemented: number;
    notSupported: number;
    error: number;
  };
}

const STATUS_MAP: Record<string, ConnectorData["paymentMethods"][0]["status"]> = {
  "✓": "supported",
  "x": "not_supported",
  "⚠": "not_implemented",
  "?": "error",
};

function parseAllConnectorMd(content: string): ConnectorData[] {
  const lines = content.split("\n");
  const connectors: ConnectorData[] = [];

  // Find the PaymentService.Authorize table
  let inAuthorizeTable = false;
  let headers: string[] = [];

  for (const line of lines) {
    // Detect table start (header separator line)
    if (line.includes("|-----") && inAuthorizeTable) {
      continue;
    }

    // Detect header row
    if (line.startsWith("| Connector") && !headers.length) {
      inAuthorizeTable = true;
      headers = line
        .split("|")
        .map((h) => h.trim())
        .filter((h) => h && h !== "Connector");
      continue;
    }

    // Parse data rows
    if (inAuthorizeTable && line.startsWith("| [")) {
      const parts = line.split("|").map((p) => p.trim());
      if (parts.length < 2) continue;

      // Extract connector name and link
      const nameMatch = parts[1]?.match(/\[([^\]]+)\]\(([^)]+)\)/);
      if (!nameMatch) continue;

      const name = nameMatch[1];
      const filePath = nameMatch[2];

      const paymentMethods: ConnectorData["paymentMethods"] = [];
      let supported = 0;
      let notImplemented = 0;
      let notSupported = 0;
      let error = 0;

      // Parse each status cell
      for (let i = 2; i < parts.length; i++) {
        const statusSymbol = parts[i]?.trim();
        const header = headers[i - 2];
        if (!header || !statusSymbol) continue;

        // Parse category/method from header like "CARD / Card"
        const [category, method] = header.split(" / ").map((s) => s.trim());

        const status = STATUS_MAP[statusSymbol] || "error";

        paymentMethods.push({
          category: category || "Unknown",
          method: method || category || "Unknown",
          status,
        });

        if (status === "supported") supported++;
        else if (status === "not_implemented") notImplemented++;
        else if (status === "not_supported") notSupported++;
        else if (status === "error") error++;
      }

      connectors.push({
        name,
        filePath,
        paymentMethods,
        stats: {
          total: paymentMethods.length,
          supported,
          notImplemented,
          notSupported,
          error,
        },
      });
    }

    // Exit table on empty line after we've seen data
    if (inAuthorizeTable && !line.trim() && connectors.length > 0) {
      break;
    }
  }

  return connectors;
}

function main() {
  const mdPath = path.resolve(
    __dirname,
    "../../../../docs-generated/all_connector.md"
  );
  const outputPath = path.resolve(__dirname, "../src/data/connectors.json");

  if (!fs.existsSync(mdPath)) {
    console.error(`❌ Input file not found: ${mdPath}`);
    process.exit(1);
  }

  console.log(`📖 Reading ${mdPath}...`);
  const content = fs.readFileSync(mdPath, "utf-8");

  console.log("🔍 Parsing connector data...");
  const connectors = parseAllConnectorMd(content);

  if (connectors.length === 0) {
    console.error("❌ No connectors parsed! Check the markdown format.");
    process.exit(1);
  }

  console.log(`✅ Parsed ${connectors.length} connectors`);

  // Ensure output directory exists
  const outputDir = path.dirname(outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  fs.writeFileSync(outputPath, JSON.stringify(connectors, null, 2));
  console.log(`💾 Written to ${outputPath}`);

  // Summary stats
  const totalNotImplemented = connectors.reduce(
    (sum, c) => sum + c.stats.notImplemented,
    0
  );
  console.log(`📊 Total not-implemented payment methods: ${totalNotImplemented}`);
}

main();
