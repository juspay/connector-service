import { fileURLToPath } from "node:url";
import { assertFramework } from "../support/framework-contract.js";

assertFramework(fileURLToPath(new URL("..", import.meta.url)));
console.log("E2E framework contract passed");
