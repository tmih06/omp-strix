import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Plugin root directory — the folder containing package.json. */
export const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
