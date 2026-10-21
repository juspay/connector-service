import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";

function files(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    return entry.isDirectory()
      ? files(path)
      : path.endsWith(".ts")
        ? [path]
        : [];
  });
}

// Check source structure with the TypeScript parser, not source-text matching.
// Scenarios declare data + register the shared runner; adapters return check data.
export function frameworkViolations(root: string): string[] {
  const violations: string[] = [];
  const sources = [
    ...files(join(root, "otp")),
    ...files(join(root, "support", "processors")),
    join(root, "support", "otp-scenarios.ts"),
  ];
  for (const path of sources) {
    const name = relative(root, path).replaceAll("\\", "/");
    const source = ts.createSourceFile(
      path,
      readFileSync(path, "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    const spec = name.startsWith("otp/superset/") && name.endsWith(".spec.ts");
    const data = name.startsWith("otp/") && !spec;
    const adapter = name.startsWith("support/processors/");
    const runner = name === "support/otp-scenarios.ts";
    const allowed = new Set([
      "structuredClone",
      "String",
      "Number",
      "Boolean",
      "Object.entries",
      "Object.fromEntries",
      "Array.from",
      "JSON.stringify",
      "JSON.parse",
    ]);
    const fail = (node: ts.Node, rule: string) =>
      violations.push(
        `${name}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}: ${rule}`,
      );
    if (
      name.startsWith("otp/") &&
      !name.startsWith("otp/superset/") &&
      name.endsWith(".spec.ts")
    ) {
      fail(
        source,
        "Connector directories contain overrides/fixtures only; move the scenario into otp/superset",
      );
      continue;
    }
    for (const statement of source.statements) {
      if (data && ts.isFunctionDeclaration(statement) && statement.name)
        allowed.add(statement.name.text);
      if (
        !ts.isImportDeclaration(statement) ||
        !ts.isStringLiteral(statement.moduleSpecifier)
      )
        continue;
      const module = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      const bindings = clause?.namedBindings;
      const imports =
        bindings && ts.isNamedImports(bindings) ? bindings.elements : [];
      const typeOnly =
        clause?.isTypeOnly ||
        (imports.length > 0 && imports.every((i) => i.isTypeOnly));
      if (spec) {
        const contracts: Record<string, readonly string[]> = {
          "@playwright/test": ["test"],
          "../../../support/cases.js": ["OtpScenario"],
          "../../../support/otp-scenarios.js": ["runOtpScenario"],
          "../../../support/otp-superset.js": ["otpSupersetCases"],
        };
        if (module === "./fixtures.js")
          for (const item of imports) allowed.add(item.name.text);
        else if (
          !contracts[module] ||
          imports.some(
            (i) => !contracts[module].includes((i.propertyName ?? i.name).text),
          ) ||
          clause?.name ||
          !imports.length
        )
          fail(
            statement,
            "Superset specs import only the shared scenario contract, runner, registration helper, test, and local fixtures",
          );
      }
      if (data && !typeOnly) {
        if (!module.endsWith("/fixtures.js") && module !== "./fixtures.js")
          fail(
            statement,
            "Connector overrides and fixtures may import only fixture builders and types",
          );
        else for (const item of imports) allowed.add(item.name.text);
      }
      if (
        adapter &&
        (module === "@playwright/test" ||
          module.startsWith("node:assert") ||
          module.endsWith("/report.js"))
      )
        fail(
          statement,
          "Processor adapters return checks; assertions and report writing belong to the shared runner",
        );
      if (
        adapter &&
        !typeOnly &&
        module.endsWith("/checks.js") &&
        imports.some(
          (i) =>
            !i.isTypeOnly &&
            !["equal", "oneOf"].includes((i.propertyName ?? i.name).text),
        )
      )
        fail(
          statement,
          "Processor adapters may construct check data but cannot assert or write it",
        );
      if (
        runner &&
        module !== "./processors/index.js" &&
        (module.startsWith("./processors/") || module === "./stripe.js")
      )
        fail(
          statement,
          "The common runner uses the processor registry, not connector-specific imports",
        );
    }
    const visit = (node: ts.Node) => {
      if (
        (spec || data) &&
        ts.isPropertyAssignment(node) &&
        (ts.isArrowFunction(node.initializer) ||
          ts.isFunctionExpression(node.initializer))
      )
        fail(
          node,
          "Scenario data and connector overrides cannot contain execution callbacks",
        );
      if (
        (adapter || runner) &&
        ts.isPropertyAccessExpression(node) &&
        node.name.text === "attach"
      )
        fail(
          node,
          "Use the shared check/report writer; do not format attachments here",
        );
      if (
        data &&
        ts.isIdentifier(node) &&
        ["process", "globalThis"].includes(node.text)
      )
        fail(
          node,
          "Fixture files contain data only; runtime environment and I/O belong in shared helpers/adapters",
        );
      if ((spec || data) && ts.isNewExpression(node))
        fail(
          node,
          "Construct runtime clients in the shared runner/adapters, not scenario data",
        );
      if (ts.isCallExpression(node)) {
        const callee = node.expression.getText(source);
        if (
          spec &&
          !allowed.has(callee) &&
          ![
            "otpSupersetCases",
            "runOtpScenario",
            "test",
            "test.describe",
          ].includes(callee)
        )
          fail(
            node,
            "Scenario specs declare data and call the common runner; custom execution/assertions belong in shared helpers",
          );
        if (
          data &&
          !allowed.has(callee) &&
          !(
            ts.isPropertyAccessExpression(node.expression) &&
            ["map", "toLowerCase", "toUpperCase"].includes(
              node.expression.name.text,
            )
          )
        )
          fail(
            node,
            "Overrides and fixture builders contain data transformations only",
          );
        if (
          adapter &&
          [
            "expect",
            "assert",
            "test",
            "verifyChecks",
            "recordChecks",
            "assertChecks",
          ].includes(callee.split(".")[0])
        )
          fail(
            node,
            "Processor adapters return standard checks rather than executing assertions/report logic",
          );
        if (spec && callee === "test") {
          const callback = node.arguments.at(-1);
          const body =
            callback && ts.isArrowFunction(callback)
              ? callback.body
              : undefined;
          const statement =
            body && ts.isBlock(body) && body.statements.length === 1
              ? body.statements[0]
              : undefined;
          const expression =
            statement &&
            ts.isExpressionStatement(statement) &&
            ts.isAwaitExpression(statement.expression)
              ? statement.expression.expression
              : undefined;
          if (
            !expression ||
            !ts.isCallExpression(expression) ||
            expression.expression.getText(source) !== "runOtpScenario"
          )
            fail(
              node,
              "Each test body must await the common runOtpScenario without custom steps",
            );
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return violations;
}

export function assertFramework(root: string) {
  const violations = frameworkViolations(root);
  if (violations.length)
    throw new Error(
      `E2E framework contract violations:\n${violations.join("\n")}`,
    );
}
