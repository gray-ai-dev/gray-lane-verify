/**
 * Gray's public entry as the published verifier knows it: where Gray publishes the signed release lists its
 * confidential VMs are checked against, and the Ed25519 public keys those lists and their freshness documents are
 * signed with. `check` (and `attest`) use them for this origin when no `--allow` is given, so a customer's whole check
 * is one command. The lists are fetched over HTTPS, but nothing about them is trusted for that: a list counts only
 * under the release key below, and a list older than a day only with a freshness document signed by the freshness key
 * (release-list.ts, release-freshness.ts). Any other origin needs `--allow` and `--release-key`.
 *
 * The values are production's in deploy/tee/release/environments.json (`release_list_url`, `stack.release_list_url`,
 * `release_public_key`, `release_freshness_public_key`); test/entries.test.ts fails when the two differ, so a key
 * rotation or a moved list changes this table, and with it the verifier's version.
 */

export interface KnownEntry {
  /** The entry's shared origin, the one customers send requests to. */
  readonly origin: string;
  /** The signed list of the entry's own releases (`attest <origin>`, the outer receipt's keyset). */
  readonly releaseList: string;
  /** The signed list of the releases a provider's confidential VM may run (`attest --via`, `/peers/<n>`). */
  readonly stackList: string;
  /** Gray's release-signing public key for both lists: 32 bytes as 64 lower-case hex. */
  readonly releaseKey: string;
  /** Gray's freshness public key for the documents beside both lists. */
  readonly freshnessKey: string;
}

export const DEFAULT_ORIGIN = "https://lane.usefallback.com";

export const KNOWN_ENTRIES: readonly KnownEntry[] = [
  {
    origin: "https://lane.usefallback.com",
    releaseList: "https://releases.usefallback.com/lane/release-list.json",
    stackList: "https://releases.usefallback.com/lane/stack/release-list.json",
    releaseKey: "4bdaf71a698e68ef2bb09a15ec7047aacad2882a14c12bae50b992a8c86694cc",
    freshnessKey: "8ff9f9c47b3c66854451655b320d620c025110461f763a5d7bcdf8b1780e3f2f",
  },
];

/** The known entry whose shared origin is exactly `origin`, or null. */
export function knownEntry(origin: URL): KnownEntry | null {
  return KNOWN_ENTRIES.find((entry) => entry.origin === origin.origin) ?? null;
}
