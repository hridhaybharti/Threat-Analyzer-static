import { execSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");

console.log("Building client...");
execSync("npm run build:client", { cwd: projectRoot, stdio: "inherit" });

console.log("Building server...");
execSync("npm run build:server", { cwd: projectRoot, stdio: "inherit" });

console.log("Build complete!");
