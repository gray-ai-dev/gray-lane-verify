/**
 * The version `gray-lane-verify --version` prints and its user agent carries, and the source commit it was built from.
 *
 * A published build (deploy/lane-verify/bundle.mjs) replaces both names below with string literals through esbuild's
 * `define`: the version is workers/packages/lane-verify/VERSION at the commit, the commit is the one the bundle was
 * built from. Run from a checkout (`node src/node/cli.ts`), the names are not defined: the version is read from the
 * VERSION file beside the package and the commit is unknown, which `--version` says.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

declare const __GRAY_LANE_VERIFY_VERSION__: string | undefined;
declare const __GRAY_LANE_VERIFY_COMMIT__: string | undefined;

/** A semantic version, as VERSION holds it. */
export const VERSION_FORM = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$/;

function checkoutVersion(): string {
  try {
    const text = readFileSync(fileURLToPath(new URL("../../VERSION", import.meta.url).href), "utf8").trim();
    return VERSION_FORM.test(text) ? text : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export const VERSION: string = typeof __GRAY_LANE_VERIFY_VERSION__ === "string" ? __GRAY_LANE_VERIFY_VERSION__ : checkoutVersion();

/** The 40-hex commit a published build was made from; null when run from a checkout. */
export const SOURCE_COMMIT: string | null = typeof __GRAY_LANE_VERIFY_COMMIT__ === "string" ? __GRAY_LANE_VERIFY_COMMIT__ : null;

/** The `--version` line. */
export function versionLine(): string {
  return SOURCE_COMMIT === null
    ? `gray-lane-verify ${VERSION} (run from a checkout: no source commit recorded)`
    : `gray-lane-verify ${VERSION} (source commit ${SOURCE_COMMIT})`;
}
