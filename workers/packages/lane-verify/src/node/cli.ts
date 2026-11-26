#!/usr/bin/env node
/**
 * `gray-lane-verify` — the customer's command line for Gray's confidential lane.
 *
 *     gray-lane-verify attest (<origin> | --via <entry> --provider <deployment id>)
 *         [(--allow <release-list.json> --release-key <64 hex>
 *           [--allow-freshness <release-list.freshness.json> --freshness-key <64 hex>]) | --allow-unpinned [--accept-unpinned]]
 *         [--accept-os-unpinned] [--provider <deployment id>] [--provider-image <image ref>]
 *         [--ca <pem>] [--nonce <64 hex>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]
 *
 *     gray-lane-verify receipt <receipt.json> --request <body file>
 *         (--origin <lane origin> [--lane-origin <x-gray-lane-origin>] | --report <report.json> --nonce <64 hex>)
 *         --allow <release-list.json> --release-key <64 hex> [--accept-os-unpinned]
 *         [--allow-freshness <release-list.freshness.json> --freshness-key <64 hex>]
 *         [--response <raw response file>] [--templates <texts.json>]
 *         [--protocol <anthropic_messages|open_ai_chat|open_ai_responses|gemini|a standard API's name>]
 *         [--peers --allow-stack <stack release-list.json> [--allow-stack-freshness <file>] [--wait <seconds>]]
 *         [--ca <pem>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]
 *
 *     gray-lane-verify check (<receipt id> | --receipt <receipt.json>) --request <body file>
 *         [--origin <entry origin, default https://lane.usefallback.com>] [--lane-origin <x-gray-lane-origin>]
 *         [--response <raw response file>] [--wait <seconds>] [--templates <texts.json>] [--protocol <...>]
 *         [--allow <list file or https URL> --release-key <64 hex> [--allow-freshness <file or URL> --freshness-key <64 hex>]]
 *         [--allow-stack <file or URL> [--allow-stack-freshness <file or URL>]] [--accept-os-unpinned]
 *         [--ca <pem>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]
 *
 * `check` is a customer's whole check of one answer in one command. With a receipt id (the answer's `x-receipt-id`)
 * it fetches the receipt with the key that made the request (`GRAY_API_KEY`, never a flag): at `--lane-origin` when
 * given (the answer's `x-gray-lane-origin`), else at `--origin`, where an entry with replicas names the replica that
 * answered in the same header and that replica is the one attested; a `503 receipt_pending` is asked again after its
 * `Retry-After`, for up to `--wait` seconds (default 30), and the same seconds cover the provider VM's records below.
 * With `--receipt` it reads a saved one. Then it does what
 * `receipt --origin [--lane-origin] --peers` does: attests the origin the receipt came from against Gray's signed
 * release list, verifies the receipt under the keyset that attestation shows, and, when the receipt names attempts in
 * a provider's confidential VM, fetches each `/peers/<n>` record and checks the VM's attestation against Gray's signed
 * stack list and its inner receipt, Gray's declared request changes and answer rewrites included. For Gray's own entry
 * (`entries.ts`) the two lists are fetched from where Gray publishes them and held to the keys built in; for any other
 * origin they are flags. It prints the checks, a summary of what they covered, `VERDICT:` and the machine line.
 *
 * `attest` generates a fresh 32-byte nonce unless `--nonce` is given (tests use the flag), fetches
 * `GET /v1/aci/attestation?nonce=...` over TLS, records the leaf certificate's SPKI with Node's
 * `tls`, and runs `verifyAttestation` with the `@phala/dcap-qvl` adapter. `--ca` **replaces** Node's
 * default WebPKI roots (it is not added to them), so pass a bundle that contains both the private
 * lane CA and the public roots if you need both. There is no insecure mode.
 *
 * Pinning policy (owner decision):
 * - plain `PASS` requires the measured compose hash and an OS image measurement from `--allow`;
 * - a release list without `os_images` prints `PASS (OS UNPINNED)` and exits 1 unless
 *   `--accept-os-unpinned` is given;
 * - `--allow` always needs `--release-key`: D22 removes the unsigned-list path entirely (pre-launch,
 *   no compatibility). A list that carries no signature is refused, so a customer cannot pin a
 *   document an intermediary could have written.
 * - without `--allow`, `attest` prints `UNPINNED` and fails; `--allow-unpinned` acknowledges it and
 *   still exits 1 unless `--accept-unpinned` is also given.
 * - D138: `--allow-freshness` with `--freshness-key` applies the relay's rule (D137) to the `--allow`
 *   list: past its own 86 400 s it stays current while the freshness document for its exact bytes counts,
 *   and never past its `expires_at`. Without them a list is current for 86 400 s after `issued_at`. Both
 *   commands print a `release_list` line with what made the list current and until when.
 *
 * `receipt` never trusts a report or keyset given to it. It requires an attested source of the receipt
 * key: `--origin <lane origin>` (fetch and fully verify a fresh attestation) or `--report` plus
 * `--nonce` (fully re-verify the saved report: ACI binding, DCAP quote, release list). A bare keyset
 * file is refused. `--allow` is required in both modes. It reads the receipt with `@gray/attest`'s
 * strict text reader and runs `verifyResponseReceiptText`. It never prints request or response
 * content, only hashes and check lines. A relay-stack receipt (S26) gets one forwarded-body check per
 * attempt, by value (`body_jcs_sha256`; its appended texts from `--templates`, SKIP when they are not
 * given), the attempt that served the answer (S32), and, with `--response`, the `events_sha256` chain
 * or `body_sha256` over the bytes received, against the receipt and against the served attempt; the
 * machine output's `stack` member lists the attempts and the served one. A receipt whose record of the
 * relay's calls stopped early (S26 `relay_stack.feed_incomplete`) prints a `relay_record` line saying
 * where and why, and `stack.feed_incomplete` carries the reason.
 *
 * `attest --via <entry> --provider <deployment id>` (docs/design/relay-outbound-only.md §5, §6) attests a relay-stack VM that
 * takes no inbound connection. It opens the entry's tunnel route (`wss://<entry>/v1/peer/tunnel/<relay>`, the wire form
 * gray-assistant uses), runs TLS inside it to the VM's workerd and fetches the report there (`tunnel.ts`). The entry's own
 * certificate is checked with WebPKI (`--ca` replaces the roots), which only gets the bytes to the entry; the VM's is
 * self-signed per boot, so the only check of it is the attestation: the same `verifyAttestation` as `attest <origin>`,
 * with no host, so the VM's keyset must bind the observed key to no domain (a key bound to a public name is a VM that
 * has not moved; attest it by its origin), and `--provider` (required) is the identity rule (`relay_pin`). The machine
 * output's `origin` is the tunnel origin `https://<entry>/v1/peer/tunnel/<relay>`, and `via` the entry.
 *
 * A relay-stack lane (plan S52) measured, after `system-ready`, which relay it serves and the image that
 * relay chose and signed for this boot. `attest` checks the relay's signature, prints the relay id, its
 * key, its token service, the lane's TLS name (and checks it is the host connected to) and the image, and
 * pins them with `--provider` and `--provider-image` (a lane without them fails the pin; `--relay` and
 * `--relay-image` are their old names, accepted but no longer documented, and one flag under both names is a usage
 * error). `receipt` requires a stack lane's receipt to name exactly the attested image (`relay_image`) and a default
 * lane's to name none.
 *
 * `receipt --peers` (docs/confidential-lane-stack-routing.md §4.8) checks a request the entry forwarded to relay stack
 * VMs. The entry's (outer) receipt names each stack VM only by a commitment; for each attempt number it names, the CLI
 * fetches `GET <origin>/v1/aci/receipts/<id>/peers/<n>` with the key that made the request (from the environment's
 * `GRAY_API_KEY`, never a flag: a command line is visible to other processes) and checks, with lines `peer:<n>:…`:
 * the stack VM's report against Gray's signed stack list (`--allow-stack`, the same `--release-key`, and with a
 * `--freshness-key` the freshness document `--allow-stack-freshness` names or, without it, the one beside the list,
 * which counts as absent when it cannot be read), that the commitment opens to that boot, and the stack VM's
 * inner receipt under its attested keyset, tied to this receipt by its `peer.entry`, with the same request in and,
 * for the attempt that served, the same answer out. The inner receipt's attempts print what the relay changed in the
 * same form as a direct receipt's (`peer:<n>:attempt:<k>:relay_changes: unchanged…` or `changed by the deployment: …`).
 * A missing inner receipt fails where the stack VM must have made one. The outer receipt holds no upstream.response for
 * an attempt a stack VM answered, so its `served_attempt` passes on `peer:<n>`, naming it, when that attempt's checks
 * tie the answer (`withPeerTie`), and is skipped otherwise. A `502 peer_receipt_unavailable` (the stack VM has not
 * signed its receipt yet) is asked again after its `Retry-After` (1 to 10 s, cut to what is left), for up to `--wait`
 * seconds (default 30); every other answer is taken as it is. `--peers` needs `--origin`. Without it the outer receipt
 * is checked as before and the machine output has no `peers` member.
 *
 * `receipt --lane-origin` (docs/design/entry-replicas.md ER6, EI8): an entry with replicas names the replica that
 * served in the response header `x-gray-lane-origin`, and only that replica holds the receipt and its peer records.
 * With the header's value, `receipt` attests that origin and fetches `peers/<n>` there instead of at `--origin`. The
 * value is not signed, so it only chooses where to ask: it must be `https://<one label>.<zone of --origin>` on port 443
 * with no credentials or path (`lane-origin.ts`), else the command fails and says why, fetching nothing; and the
 * receipt still verifies only against the keyset attested there, which must hold a TLS record for that host. Without
 * the flag (a single entry sends no header) nothing changes.
 *
 * `attest <origin>` and `attest --via <entry>` for Gray's own entry with neither `--allow` nor `--allow-unpinned` pin
 * the list Gray publishes for it (the entry's own list for an origin, the stack list for `--via`) under the built-in
 * keys, as `check` does.
 *
 * `receipt` and `check` on a receipt of a request that reached the VM through Gray's API (docs/design/one-address.md:
 * `api_version` `aci/1+gray-api`, `arrival: "gray_api"`) run every check as for any receipt; the one more,
 * `client_connection`, fails, because the client's TLS ended at Cloudflare and not in the VM. When it is the only failure
 * the verdict is `VALID, NOT END TO END: arrived through Gray's API` and the exit code 3: the receipt is genuine, and the
 * leg from the client to the VM is not covered. The machine output's `ok` is false and its `arrival` is `gray_api`.
 *
 * `receipt` and `check` on a receipt of a request Gray translated onto another text API for a provider's own API
 * (`request.translated`, docs/design/lane-provider-routes.md section 10) replay the translation (receipt.ts): the
 * `translation` line names the two APIs and the dropped fields, and `forwarded_body_hash` passes when the forwarded
 * body is that translation of the customer's bytes with Gray's declared ops. The verdict is as for any receipt. The
 * machine output gains `translation` (`from`, `to`, `dropped`, `output_cap`), only on such receipts, and `check`'s
 * `covered:` block two `translated` lines: what the replay proves for the request, and that the answer's translation
 * back is not replayed.
 *
 * `receipt` and `check` on a receipt of a standard API (docs/design/standard-media-at-entry.md section 2.4: embeddings,
 * rerank, images, speech, transcriptions, translations, videos, System One) replay Gray's declared ops under
 * `gray-lane-rewrites-v2` (receipt.ts). When the request was a `multipart/form-data` form and Gray changed a field of
 * it (`set_form_field`, `remove_form_field`), the replay reads the form by the boundary of its own first line, so the
 * command takes nothing more than for a JSON request: `--request` is the whole body as sent, files included. A body
 * that does not begin with its boundary line does not replay.
 *
 * `receipt --peers` and `check` always ask the entry for each `/peers/<n>` record, whatever the time (1.7.1). The entry
 * keeps a receipt and its peer records for the outer receipt's signed `retention_seconds` after the answer ends (30
 * days for an entry that persists its receipts, 1.8.0), and an hour, in memory, for a receipt without the member. When
 * it answers `404 receipt_not_found` for a record after the outer receipt's signed `served_at` plus that retention plus
 * 3 900 s (the longest request and 300 s of clock difference; 7 500 s in all without the member, as in 1.7.1), the line
 * is `EXPIRED peer:<n>:fetch` and, when no check failed, the verdict is `EXPIRED`, exit code 4: that attempt was not
 * checked, and nothing says it was changed. Inside that window the same answer is a FAIL, and so is every other
 * answer. Only a saved receipt gets there: `check <receipt id>` has no signed time before it holds the receipt, so a
 * receipt the entry no longer gives is a FAIL.
 *
 * An earlier boot's receipt (1.8.0, docs/design/persisted-receipts.md sections 6 and 7): when the receipt's
 * `workload_keyset_digest` is not the keyset the live attestation of the origin shows, `receipt --origin` and `check`
 * fetch `GET <origin>/v1/aci/receipts/<id>/attestation` with the key that made the request (GRAY_API_KEY): the boot
 * report the entry stored for that boot. Its `keyset_digest` must be the receipt's and its nonce
 * `hex(SHA-256("gray-lane-boot-report/v1" || keyset_digest))`. The report is verified as `--report --nonce` verifies
 * one, with the quote checked against the collateral the boot stored, at its `collateral_check.checked_at`, or, when it
 * stored none, against live collateral (the line says which), its keyset's `not_after` at the receipt's `served_at`,
 * and its compose taken from the release list at `served_at`: a current release, or one in the list's `superseded`
 * array whose `superseded_at` + 300 s is not before `served_at` (`release_at`). The live attestation must still pass.
 * The transcript says `attested at boot, stored report` with the collateral's issue date and TCB status, and the
 * machine output has `stored_attestation`. A `503 receipt_lookup_unavailable` (the entry's receipt store did not
 * answer) is asked again after its `Retry-After` within `--wait`, for the receipt, its stored report and its peer
 * records. A stack VM's record is checked against the stack list at the outer receipt's `served_at` the same way, and
 * its keyset's `not_after` at that time too.
 *
 * The stored collateral's time (`collateral_window`): with A = `attested_at`, C = `collateral_check.checked_at`, S =
 * `served_at` and N = now, A - 300 <= C <= N + 300 and C >= S - 2 days - 300 (the entry refreshes it daily). Online,
 * `retention_window`: S >= N - (`retention_seconds` + 3 900). `collateralWindowCheck` says why.
 *
 * `--boot-report <file>` (1.8.0): the receipt's saved `/attestation` answer, for `receipt` (in place of `--origin` or
 * `--report`) and `check --receipt`. Nothing is asked of the entry for it and no origin is attested, so a saved receipt
 * stays checkable after the entry's retention or a move to another app id, with the signed release list kept beside
 * it (`--allow`). `retention_window` does not apply and says so; `collateral_window` does.
 *
 * A receipt whose answer the client left (`served_as: client_left`, 1.7.1) commits to every event or body byte the
 * entry queued for the client. With `--response` bytes shorter than that, which do not end the answer by its protocol,
 * the digest line is `PARTIAL` and, when no check failed, the verdict is `PARTIAL`, exit code 5: the receipt and the
 * request verified, and the answer's digest could not be recomputed from the bytes held. The raw `body_hash` is not
 * compared on such a receipt, since keep-alive comments the entry queued are in it. Bytes that end the answer
 * ([DONE], response.completed, response.incomplete, response.failed, message_stop, a whole JSON body) and do not match
 * stay a FAIL, and so do any bytes of a receipt with another `served_as` or `replaced_error: true`, and an event against
 * a receipt of a client that left before any answer. Precedence: FAIL (1), then PARTIAL (5), then EXPIRED (4), then
 * VALID, NOT END TO END (3), then PASS.
 *
 * Exit codes: 0 every check passed and the requested pinning was accepted, 1 a check failed or the
 * pinning was not accepted (for `check`, also: the entry did not give the receipt), 2 usage or I/O error,
 * 3 (`receipt`, `check`) the receipt is valid but the request arrived through Gray's API, so it is not end to end,
 * 4 (`receipt --peers`, `check`) no check failed, and the entry no longer holds a peer record past its retention,
 * 5 (`receipt`, `check`) no check failed, and the `--response` bytes are shorter than what the entry queued for a client
 * that left (`served_as: client_left`).
 */
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { request as httpsRequest } from "node:https";
import { pathToFileURL } from "node:url";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { adoptKeyset, parseAttestationReportText, parseReceiptText, RECEIPT_ARRIVAL_GRAY_API, reportKeysetValue, type RelayStackChanges, type SealedKeyset } from "@gray/attest";
import { get, isObject, parseStrict, toJsonString, type Json, type JsonObject } from "@gray/json";
import { isRewriteApi } from "@gray/lane";
import { verifyAttestation, type AttestationVerification, type QuoteAppraisal, type QuoteVerifier, type VerifyCheck } from "../attestation.ts";
import { LANE_ORIGIN_HEADER, readLaneOrigin } from "../lane-origin.ts";
import { verifyResponseReceiptText, type ReceiptCheck, type ReceiptProtocol, type StackReceiptSummary, type TemplateText } from "../receipt.ts";
import type { PeerReleaseList } from "../peer.ts";
import { ENTRY_RECEIPT_RETENTION_SECONDS, PEER_RECORD_RETENTION_MARGIN_SECONDS, RECEIPT_CLOCK_MARGIN_SECONDS, peerNumbersToFetch, peerRecordRetentionBound, readPeerAnswerText, verifyPeerReceipts, withPeerTie, type PeerAnswer, type PeerAnswerError, type PeerReceiptsVerification } from "../peer-receipt.ts";
import { isStackRelayImage, STACK_RELAY_ID_PATTERN, type StackBootResult } from "../stack-boot.ts";
import { MAX_RELEASE_LIST_BYTES, RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS, osImageProvenance, readReleaseListText, releaseListAt, type ReleaseList } from "../release-list.ts";
import { bootReportNonce, collateralIssueDate, readStoredAttestationText, type StoredAttestation, type StoredCollateral } from "../stored-attestation.ts";
import { releaseFreshnessLocation } from "../release-freshness.ts";
import { DEFAULT_ORIGIN, knownEntry, type KnownEntry } from "./entries.ts";
import { fetchThroughTunnel, TunnelRefusedError, tunnelOrigin } from "./tunnel.ts";
import { VERSION, versionLine } from "./version.ts";

const MAX_REPORT_BYTES = 1024 * 1024;
/** The largest receipt `check` reads: an outer receipt with its attempts, with room. */
const MAX_RECEIPT_BYTES = 1024 * 1024;

/** Flags that take no value; every other `--name` consumes the next argument. */
const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "help",
  "version",
  "allow-unpinned",
  "accept-unpinned",
  "accept-os-unpinned",
  "peers",
]);

/**
 * Old flag names, still accepted and no longer documented (user-facing text names providers and their deployments,
 * owner decision 2026-11-16). The parser files a value under the new name; giving both names of one flag is an error.
 */
const FLAG_ALIASES: ReadonlyMap<string, string> = new Map([
  ["relay", "provider"],
  ["relay-image", "provider-image"],
]);

class UsageError extends Error {
  override readonly name = "UsageError";
}

interface ParsedArgs {
  readonly command: string;
  readonly positional: readonly string[];
  /** Keyed by the new name of an aliased flag. */
  readonly flags: ReadonlyMap<string, string>;
  /** The name each valued flag was given under (an old name for an alias), for messages. */
  readonly spelled: ReadonlyMap<string, string>;
}

/** Where the CLI writes: the process's streams by default; a test passes collectors (D60). */
export interface CliIo {
  out(text: string): void;
  err(text: string): void;
}

const PROCESS_IO: CliIo = {
  out: (text) => process.stdout.write(text),
  err: (text) => process.stderr.write(text),
};

let sink: CliIo = PROCESS_IO;

function out(text: string): void {
  sink.out(text);
}

function err(text: string): void {
  sink.err(text);
}

/** One GET answer read up to a bound. */
export interface FetchedText {
  readonly status: number;
  readonly text: string;
  /** The answer's headers, names in lower case (`check` reads `retry-after` and `x-gray-lane-origin`). */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * How the CLI asks an origin over TLS: `GET <url>` for an attestation report (with the leaf certificate's SPKI) and
 * `GET <url>` with the customer's key; `getPublic` reads a published file (a release list) with Node's own trust
 * store, never `--ca`; `sleep` waits out a `Retry-After`. Node's `https` and timers by default; a test passes one that
 * records each URL (D60). The two optional members default to Node's.
 */
export interface CliNet {
  attestation(url: URL, ca: string | undefined): Promise<FetchedReport>;
  getWithKey(url: URL, apiKey: string, ca: string | undefined, maxBytes: number): Promise<FetchedText>;
  getPublic?(url: URL, maxBytes: number): Promise<FetchedText>;
  sleep?(ms: number): Promise<void>;
}

export const NODE_NET: CliNet = {
  attestation: (url, ca) => httpsAttestation(url, ca),
  getWithKey: (url, apiKey, ca, maxBytes) => httpsWithKey(url, apiKey, ca, maxBytes),
  getPublic: (url, maxBytes) => httpsGet(url, undefined, undefined, maxBytes),
  sleep: (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)),
};

let net: CliNet = NODE_NET;

/**
 * The CLI's entry point, exported so a test runs the cases in-process (D60): `io` collects the
 * output, the default writes to the process's streams; `transport` is how it reaches an origin.
 * Returns the exit code; it never exits.
 */
export async function main(argv: readonly string[], io: CliIo = PROCESS_IO, transport: CliNet = NODE_NET): Promise<number> {
  const previous = sink;
  const previousNet = net;
  sink = io;
  net = transport;
  try {
    return await run(argv);
  } finally {
    sink = previous;
    net = previousNet;
  }
}

async function run(argv: readonly string[]): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    err(`gray-lane-verify: ${messageOf(error)}\n${usage()}`);
    return 2;
  }
  if (args.flags.has("help") || args.command === "help") {
    out(usage());
    return 0;
  }
  if (args.flags.has("version")) {
    out(`${versionLine()}\n`);
    return 0;
  }
  try {
    if (args.command === "attest") return await attestCommand(args);
    if (args.command === "receipt") return await receiptCommand(args);
    if (args.command === "check") return await checkCommand(args);
    err(`gray-lane-verify: unknown command ${JSON.stringify(args.command)}\n${usage()}`);
    return 2;
  } catch (error) {
    if (error instanceof UsageError) {
      err(`gray-lane-verify: ${error.message}\n`);
      return 2;
    }
    err(`gray-lane-verify: ${messageOf(error)}\n`);
    return 1;
  }
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  const spelled = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    if (arg === "--help" || arg === "-h") {
      flags.set("help", "true");
      continue;
    }
    if (arg === "--version") {
      flags.set("version", "true");
      continue;
    }
    if (arg.startsWith("--")) {
      const equals = arg.indexOf("=");
      const name = equals < 0 ? arg.slice(2) : arg.slice(2, equals);
      if (name === "") throw new UsageError("an empty option name");
      if (BOOLEAN_FLAGS.has(name)) {
        if (equals >= 0) throw new UsageError(`--${name} takes no value`);
        flags.set(name, "true");
        continue;
      }
      const key = FLAG_ALIASES.get(name) ?? name;
      const earlier = spelled.get(key);
      if (earlier !== undefined && earlier !== name) throw new UsageError(`--${key === name ? earlier : name} is the old name of --${key}: give one of them`);
      spelled.set(key, name);
      if (equals >= 0) {
        flags.set(key, arg.slice(equals + 1));
        continue;
      }
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`--${name} needs a value`);
      flags.set(key, value);
      index += 1;
      continue;
    }
    positional.push(arg);
  }
  if (positional.length === 0) {
    if (flags.has("help")) return { command: "help", positional: [], flags, spelled };
    if (flags.has("version")) return { command: "version", positional: [], flags, spelled };
    throw new UsageError("missing command");
  }
  return { command: positional[0] as string, positional: positional.slice(1), flags, spelled };
}

function usage(): string {
  return [
    "usage: gray-lane-verify attest (<origin> | --via <entry> --provider <deployment id>)",
    "           [(--allow <release-list.json> --release-key <64 hex>",
    "             [--allow-freshness <file> --freshness-key <64 hex>]) | --allow-unpinned [--accept-unpinned]]",
    "           [--accept-os-unpinned] [--provider <deployment id>] [--provider-image <image ref>]",
    "           [--ca <pem>] [--nonce <64 hex>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]",
    "       gray-lane-verify receipt <receipt.json> --request <body file>",
    "           (--origin <lane origin> [--lane-origin <url>] | --report <report.json> --nonce <64 hex>",
    "            | --boot-report <file>)",
    "           --allow <release-list.json> --release-key <64 hex> [--accept-os-unpinned]",
    "           [--allow-freshness <file> --freshness-key <64 hex>]",
    "           [--response <raw response file>] [--templates <texts.json>]",
    "           [--protocol <anthropic_messages|open_ai_chat|open_ai_responses|gemini|...>]",
    "           [--peers --allow-stack <stack release-list.json> [--allow-stack-freshness <file>] [--wait <seconds>]]",
    "           [--ca <pem>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]",
    "       gray-lane-verify check (<receipt id> | --receipt <receipt.json>) --request <body file>",
    "           [--boot-report <file>, with --receipt]",
    "           [--origin <entry origin>] [--lane-origin <url>] [--response <raw response file>] [--wait <seconds>]",
    "           [--templates <texts.json>] [--protocol <...>] [--accept-os-unpinned]",
    "           [--allow <file or URL> --release-key <64 hex> [--allow-freshness <file or URL> --freshness-key <64 hex>]]",
    "           [--allow-stack <file or URL> [--allow-stack-freshness <file or URL>]]",
    "           [--ca <pem>] [--now <unix>] [--pccs <url>] [--verifier-module <file>]",
    "",
    "check (one answer, every step):",
    "  <receipt id>            the answer's x-receipt-id; fetched with the key that made the request,",
    "                          taken from the environment as GRAY_API_KEY (never a flag, never printed)",
    "  --receipt <file>        a receipt you saved instead; GRAY_API_KEY is then needed only when the",
    "                          receipt names attempts in a provider's VM",
    "  --request <file>        the exact request body you sent (a multipart form whole, files included)",
    "  --response <file>       the raw bytes you received (SSE framing included): also checks the answer",
    `  --origin <url>          the entry you sent the request to (default ${DEFAULT_ORIGIN})`,
    "  --lane-origin <url>     the answer's x-gray-lane-origin header, when it had one",
    "  --wait <seconds>        how long to keep asking while the entry answers 503 receipt_pending or",
    "                          receipt_lookup_unavailable, or 502 peer_receipt_unavailable for a provider",
    "                          VM's record (default 30, in all)",
    `  For ${DEFAULT_ORIGIN} the release lists are fetched from where Gray publishes them and accepted`,
    "  only under the release and freshness keys built into this tool (--version names its source commit).",
    "  For another origin pass --allow, --release-key and, for a provider's VM, --allow-stack.",
    "",
    "pinning:",
    "  --allow <file>          pin the measured compose hash and OS image(s) from the signed release list",
    "                          (a file, or an https URL it is fetched from; the signature decides, not the host)",
    "  --release-key <64 hex>  Gray's release-signing public key; required with --allow (D22)",
    "  --allow-freshness <file>  the freshness document Gray publishes beside the list",
    "                          (release-list.freshness.json): keeps a list older than a day current",
    "  --freshness-key <64 hex>  Gray's freshness public key; required with --allow-freshness (D138)",
    "  --allow-unpinned        no release list: print UNPINNED, fail unless --accept-unpinned",
    "  --accept-unpinned       with --allow-unpinned: exit 0 on PASS (UNPINNED)",
    "  --accept-os-unpinned    with a release list that has no os_images: exit 0 on",
    "                          PASS (OS UNPINNED); without it that verdict exits 1",
    "",
    "  --via <entry>           attest: reach a provider's deployment VM through Gray's entry (https://<entry>),",
    "                          TLS end to end through its tunnel; needs --provider, and takes no <origin>",
    "  --provider <deployment id>  the lane must serve this deployment (its measured identity)",
    "  --provider-image <ref>  and run this image, signed by the provider (<registry>/<repo>@sha256:<64 hex>)",
    "",
    "  --lane-origin <url>     receipt: the response's x-gray-lane-origin header, the entry replica that",
    "                          served; attest it and ask it for the receipt's records instead of --origin.",
    "                          Only https://<name>.<zone of --origin> on port 443; anything else fails",
    "",
    "  --peers                 receipt: also check each deployment VM the entry forwarded to, with the",
    "                          records the entry serves for the receipt (needs --origin, and the key that",
    "                          made the request in the environment as GRAY_API_KEY)",
    "  --allow-stack <file>    with --peers: Gray's signed stack release list (lane/stack/release-list.json),",
    "                          under the same --release-key",
    "  --allow-stack-freshness <file>  its freshness document, under the same --freshness-key. Without it, when a",
    "                          freshness key is pinned, the .freshness.json beside --allow-stack is read, and",
    "                          one that cannot be read leaves the list current for a day after its issued_at",
    "  --wait <seconds>        with --origin: how long to keep asking while the entry answers 503",
    "                          receipt_lookup_unavailable for an earlier boot's stored report, or, with",
    "                          --peers, 502 peer_receipt_unavailable for a VM's record (default 30)",
    "",
    "  A receipt whose keyset is not the one the origin attests now was signed by an earlier boot: receipt",
    "  --origin and check then verify the boot report the entry stored for it (GRAY_API_KEY reads it)",
    "  and print 'attested at boot, stored report' with the collateral's issue date and TCB status.",
    "  --boot-report <file>    receipt, and check with --receipt: the receipt's saved",
    "                          GET /v1/aci/receipts/<id>/attestation answer, used instead of asking the",
    "                          entry; no origin is attested. With the receipt and the signed release list",
    "                          (--allow, a file) it checks a receipt after the entry's 30 days or after",
    "                          the entry moved to another app id. The stored collateral must still have",
    "                          been checked at most two days before the receipt was served",
    "",
    "  Plain PASS requires both a pinned compose hash and a pinned OS image.",
    "  --ca <pem> replaces Node's default trust store; it is not added to it.",
    "  --verifier-module is an advanced test/relying-party seam.",
    "",
    "exit codes: 0 all checks passed and pinning accepted, 1 a check failed or pinning was not",
    "            accepted (check: or the entry did not give the receipt), 2 usage/IO error,",
    "            3 (receipt, check) VALID, NOT END TO END: the receipt is genuine, and the request",
    "            arrived through Gray's API, so your connection did not end in the attested VM,",
    "            4 (receipt --peers, check) EXPIRED: no check failed, and the entry no longer holds",
    "            a provider VM's record: asked after the saved receipt's served_at + its signed",
    "            retention_seconds + 3900 s (an hour of retention on a receipt without the member,",
    "            7500 s in all), so it was not checked,",
    "            5 (receipt, check) PARTIAL: no check failed, and the entry recorded served_as:",
    "            client_left: the --response bytes are shorter than what it queued for the client",
    "            and do not end the answer, so the response digest was not recomputed",
    "",
  ].join("\n");
}

interface PinFlags {
  readonly allowPath: string | null;
  readonly allowUnpinned: boolean;
  readonly acceptUnpinned: boolean;
  readonly acceptOsUnpinned: boolean;
  /** Gray's release-signing key: required with `--allow` (D22, no unsigned-list path). */
  readonly releaseKey: Uint8Array | null;
  /** D138: the freshness document and Gray's freshness key, both or neither. */
  readonly freshnessPath: string | null;
  readonly freshnessKey: Uint8Array | null;
}

function readPinFlags(args: ParsedArgs, command: "attest" | "receipt"): PinFlags {
  const allowPath = args.flags.get("allow") ?? null;
  const allowUnpinned = args.flags.has("allow-unpinned");
  const acceptUnpinned = args.flags.has("accept-unpinned");
  const acceptOsUnpinned = args.flags.has("accept-os-unpinned");
  const releaseKey = args.flags.has("release-key") ? parseKey(args.flags.get("release-key") as string, "--release-key") : null;
  const freshnessPath = args.flags.get("allow-freshness") ?? null;
  const freshnessKey = args.flags.has("freshness-key") ? parseKey(args.flags.get("freshness-key") as string, "--freshness-key") : null;
  if (allowPath !== null && allowUnpinned) throw new UsageError("pass --allow or --allow-unpinned, not both");
  if (command === "receipt" && allowUnpinned) {
    throw new UsageError("receipt needs an attested, pinned build: pass --allow <release-list.json>");
  }
  if (acceptUnpinned && !allowUnpinned) throw new UsageError("--accept-unpinned is only meaningful with --allow-unpinned");
  if (command === "receipt" && acceptUnpinned) throw new UsageError("receipt does not accept --accept-unpinned");
  if (acceptOsUnpinned && allowPath === null) throw new UsageError("--accept-os-unpinned is only meaningful with --allow");
  if (releaseKey !== null && allowPath === null) throw new UsageError("--release-key is only meaningful with --allow");
  // D22: `--allow` is only ever a signed list. Without a key there is no way to tell Gray's list
  // from a document an intermediary wrote, so it is a usage refusal, never a silent unsigned read.
  if (allowPath !== null && releaseKey === null) {
    throw new UsageError("--allow needs --release-key <64 hex>: the signed release list Gray publishes");
  }
  if ((freshnessPath === null) !== (freshnessKey === null)) {
    throw new UsageError("--allow-freshness and --freshness-key go together: the document Gray publishes beside the list and its freshness public key");
  }
  if (freshnessPath !== null && allowPath === null) throw new UsageError("--allow-freshness is only meaningful with --allow");
  if (freshnessKey !== null && releaseKey !== null && freshnessKey.every((byte, index) => byte === releaseKey[index])) {
    throw new UsageError("--freshness-key is Gray's freshness public key, not the release key (D134)");
  }
  return { allowPath, allowUnpinned, acceptUnpinned, acceptOsUnpinned, releaseKey, freshnessPath, freshnessKey };
}

/** A pinned Ed25519 public key: 32 bytes as 64 lower-case hex. */
function parseKey(text: string, flag: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(text)) throw new UsageError(`${flag} must be 32 bytes as 64 lower-case hex digits`);
  const key = new Uint8Array(32);
  for (let index = 0; index < 32; index += 1) key[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  return key;
}

async function attestCommand(given: ParsedArgs): Promise<number> {
  assertFlags(given, ["allow", "allow-unpinned", "accept-unpinned", "accept-os-unpinned", "release-key", "allow-freshness", "freshness-key", "provider", "provider-image", "ca", "nonce", "now", "pccs", "verifier-module", "via"]);
  const target = readAttestTarget(given);
  // Gray's own entry: its published list (the stack list for a provider's VM, --via) under the built-in keys.
  const defaults = entryDefaults(given, target.via ?? target.origin, target.via === null ? "entry" : "stack");
  const args = defaults.args;
  const pins = readPinFlags(args, "attest");
  const relayPins = readRelayPins(args);
  const nonce = parseNonce(args.flags.get("nonce") ?? randomBytes(32).toString("hex"));
  const ca = args.flags.has("ca") ? readText(args.flags.get("ca") as string, "CA certificate") : undefined;
  const nowSecs = args.flags.has("now") ? parseUnixSeconds(args.flags.get("now") as string) : nowSeconds();
  const pinned = pins.allowPath === null || pins.releaseKey === null ? null : await loadReleaseList(pins.allowPath, pins.releaseKey, nowSecs, { ...pins, freshnessOptional: defaults.entry !== null });
  const release = pinned?.list ?? null;
  const quoteVerifier = await loadQuoteVerifier(args, nowSecs);
  let fetched: FetchedReport;
  try {
    fetched = target.via === null ? await fetchAttestation(target.origin, nonce, ca) : await fetchAttestationVia(target.via, target.relayId as string, nonce, ca);
  } catch (error) {
    if (error instanceof TunnelRefusedError) throw new UsageError(`cannot attest ${target.shown}: ${error.message}`);
    throw new UsageError(`cannot fetch ${target.shown}/v1/aci/attestation: ${messageOf(error)}`);
  }
  const report = parseReportText(fetched.text, "the attestation report");
  const verification = await verifyReport(report, {
    nonce,
    release,
    tlsSpkiSha256: fetched.spkiSha256,
    // relay-outbound-only §3.3, §5: through the entry the client connected to the entry's name, which no VM identity
    // names. No host: the keyset must bind the observed key to no domain, and --provider is the identity rule.
    ...(target.via === null ? { host: target.origin.hostname } : {}),
    nowSecs,
    quoteVerifier,
    ...relayPins,
  });

  out(`gray-lane-verify attest ${target.via === null ? target.shown : `--via ${target.via.origin} --provider ${target.relayId as string}`}\n`);
  out(`nonce ${nonce}\n`);
  if (defaults.line !== null) out(`${defaults.line}\n`);
  if (pinned !== null) out(`${pinned.line}\n`);
  printChecks(verification.checks);
  printRelay(verification.stackBoot);
  if (!verification.composePinned) {
    out("UNPINNED: no release list; the measured compose hash and the OS image are not pinned.\n");
  } else if (!verification.osPinned) {
    out("OS UNPINNED: the release list pins the compose hash but no OS image measurement.\n");
  }
  const outcome = attestOutcome(verification, pins);
  out(`VERDICT: ${outcome.verdict}\n`);
  const machine: JsonObject = {
    command: "attest",
    ok: outcome.accepted,
    verdict: outcome.verdict,
    origin: target.shown,
    ...(target.via === null ? {} : { via: target.via.origin }),
    nonce,
    pinned: verification.pinned,
    compose_pinned: verification.composePinned,
    os_pinned: verification.osPinned,
    tee_type: verification.teeType,
    keyset_digest: verification.keysetDigest,
    report_data: verification.reportData,
    compose_hash: verification.composeHash,
    os_image_hash: verification.osImageHash,
    tls_spki_sha256: verification.tlsSpkiSha256,
    relay: relayMachine(verification.stackBoot),
    checks: verification.checks.map(checkValue),
    ...(pinned === null ? {} : { release_list: pinned.machine }),
  };
  out(`${toJsonString(machine)}\n`);
  return outcome.accepted ? 0 : 1;
}

/** What `attest` dials: an origin, or a relay's VM through an entry (`--via`, `--relay`). */
interface AttestTarget {
  /** The origin printed and put in the machine output: the lane's, or the tunnel origin `https://<entry>/v1/peer/tunnel/<relay>`. */
  readonly shown: string;
  /** The lane's origin; with `--via`, the entry's. */
  readonly origin: URL;
  /** The entry with `--via`, else null. */
  readonly via: URL | null;
  readonly relayId: string | null;
}

/** `attest <origin>` or `attest --via <entry> --provider <deployment id>`, never both (relay-outbound-only §5). */
function readAttestTarget(args: ParsedArgs): AttestTarget {
  const via = args.flags.get("via");
  if (via === undefined) {
    if (args.positional.length !== 1) throw new UsageError("attest needs exactly one origin, or --via <entry> --provider <deployment id>");
    const origin = normalizeOrigin(args.positional[0] as string);
    return { shown: origin.origin, origin, via: null, relayId: null };
  }
  if (args.positional.length !== 0) throw new UsageError("attest takes an origin or --via <entry>, not both");
  const relayId = args.flags.get("provider");
  if (relayId === undefined) throw new UsageError("--via needs --provider <deployment id>: the deployment whose VM the entry's tunnel reaches, and the identity it must serve");
  if (!STACK_RELAY_ID_PATTERN.test(relayId) || relayId === "." || relayId === "..") throw new UsageError(DEPLOYMENT_ID_FORM);
  const entry = normalizeOrigin(via);
  return { shown: tunnelOrigin(entry, relayId), origin: entry, via: entry, relayId };
}

/** `GET /v1/aci/attestation?nonce=…` from a relay's VM through the entry's tunnel (`tunnel.ts`). */
async function fetchAttestationVia(entry: URL, relayId: string, nonce: string, ca: string | undefined): Promise<FetchedReport> {
  const fetched = await fetchThroughTunnel({
    entry,
    relayId,
    path: `/v1/aci/attestation?nonce=${nonce}`,
    ...(ca === undefined ? {} : { ca }),
    userAgent: `gray-lane-verify/${VERSION}`,
    timeoutMs: 20_000,
    maxBytes: MAX_REPORT_BYTES,
  });
  if (fetched.status !== 200) throw new Error(`the VM answered ${String(fetched.status)} through the entry`);
  return { text: fetched.text, spkiSha256: fetched.spkiSha256 };
}

const DEPLOYMENT_ID_FORM = "--provider must be a deployment id: 1-128 characters of A-Z a-z 0-9 _ . : -";

/** `--provider` and `--provider-image` (S52; old names `--relay`, `--relay-image`), checked for their forms before anything is fetched. */
function readRelayPins(args: ParsedArgs): { readonly expectedRelayId?: string; readonly expectedRelayImage?: string } {
  const relay = args.flags.get("provider");
  const image = args.flags.get("provider-image");
  if (relay !== undefined && !STACK_RELAY_ID_PATTERN.test(relay)) throw new UsageError(DEPLOYMENT_ID_FORM);
  if (image !== undefined && !isStackRelayImage(image)) throw new UsageError("--provider-image must be <registry>/<repository>@sha256:<64 hex>");
  return { ...(relay === undefined ? {} : { expectedRelayId: relay }), ...(image === undefined ? {} : { expectedRelayImage: image }) };
}

/** The sealed boot's relay identity and image (S52), when the lane is a relay-stack lane whose events verified. */
function sealedRelay(stackBoot: StackBootResult | null) {
  return stackBoot !== null && stackBoot.ok && stackBoot.facts !== null && stackBoot.facts.phase === "sealed" ? stackBoot.facts : null;
}

function printRelay(stackBoot: StackBootResult | null): void {
  const facts = sealedRelay(stackBoot);
  if (facts === null) return;
  out(`deployment ${transcriptText(facts.identity.relayId)}\n`);
  out(`deployment key ${transcriptText(facts.identity.publicKey)}\n`);
  out(`deployment token service ${transcriptText(facts.identity.tokenUrl)}\n`);
  out(`deployment tls domain ${facts.identity.tlsDomain === null ? "(none: reached through the entry)" : transcriptText(facts.identity.tlsDomain)}\n`);
  out(`provider image ${transcriptText(facts.image.image)} (signed by the deployment key)\n`);
}

function relayMachine(stackBoot: StackBootResult | null): JsonObject | null {
  const facts = sealedRelay(stackBoot);
  if (facts === null) return null;
  return {
    relay_id: facts.identity.relayId,
    public_key: facts.identity.publicKey,
    token_url: facts.identity.tokenUrl,
    tls_domain: facts.identity.tlsDomain,
    image: facts.image.image,
  };
}

/**
 * S52/S55: the relay image an attested lane's receipts must name: the sealed boot's image, or null for a
 * default-layout lane. Undefined only when the events did not verify, which already failed the attestation.
 */
function attestedRelayImage(stackBoot: StackBootResult | null): string | null | undefined {
  if (stackBoot === null || !stackBoot.ok) return undefined;
  if (stackBoot.facts === null) return null;
  return stackBoot.facts.phase === "sealed" ? stackBoot.facts.image.image : undefined;
}

interface Verdict {
  readonly accepted: boolean;
  readonly verdict: string;
}

/**
 * What the CLI's pinning policy says about an attestation. The library's `ok` only says that every
 * check it ran passed; this function adds the owner's pinning requirement (F-04, F-05).
 */
function attestOutcome(verification: AttestationVerification, pins: PinFlags): Verdict {
  if (!verification.ok) return { accepted: false, verdict: "FAIL" };
  if (pins.allowPath === null) {
    if (!pins.allowUnpinned) return { accepted: false, verdict: "FAIL (UNPINNED)" };
    if (!pins.acceptUnpinned) return { accepted: false, verdict: "UNPINNED" };
    return { accepted: true, verdict: "PASS (UNPINNED)" };
  }
  if (!verification.composePinned) return { accepted: false, verdict: "FAIL (UNPINNED)" };
  if (!verification.osPinned) {
    return { accepted: pins.acceptOsUnpinned, verdict: "PASS (OS UNPINNED)" };
  }
  return { accepted: true, verdict: "PASS" };
}

export interface FetchedReport {
  readonly text: string;
  readonly spkiSha256: string;
}

function fetchAttestation(origin: URL, nonce: string, ca: string | undefined): Promise<FetchedReport> {
  const url = new URL("/v1/aci/attestation", origin);
  url.searchParams.set("nonce", nonce);
  return net.attestation(url, ca);
}

function httpsAttestation(url: URL, ca: string | undefined): Promise<FetchedReport> {
  return new Promise((resolvePromise, rejectPromise) => {
    const request = httpsRequest(
      url.toString(),
      {
        method: "GET",
        ...(ca === undefined ? {} : { ca }),
        headers: { accept: "application/json", "user-agent": `gray-lane-verify/${VERSION}` },
        timeout: 20_000,
      },
      (response) => {
        const socket = response.socket as TLSSocket;
        const certificate = socket.getPeerCertificate(false);
        if (certificate === null || certificate === undefined || certificate.raw === undefined) {
          response.resume();
          rejectPromise(new Error("the server presented no TLS certificate"));
          return;
        }
        let spkiSha256: string;
        try {
          spkiSha256 = spkiOf(certificate);
        } catch (error) {
          response.resume();
          rejectPromise(new Error(`cannot read the server's TLS SPKI: ${messageOf(error)}`));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_REPORT_BYTES) {
            response.destroy(new Error(`the attestation report is larger than ${MAX_REPORT_BYTES} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", rejectPromise);
        response.on("end", () => {
          if (response.statusCode !== 200) {
            rejectPromise(new Error(`${url.origin} answered ${String(response.statusCode)}`));
            return;
          }
          resolvePromise({ text: Buffer.concat(chunks).toString("utf8"), spkiSha256 });
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("the attestation request timed out")));
    request.on("error", rejectPromise);
    request.end();
  });
}

/**
 * SHA-256 over the DER SubjectPublicKeyInfo of the certificate a TLS peer presented.
 *
 * Not `PeerCertificate.pubkey`: that member is the SPKI DER for an RSA key, but the raw 65-byte EC
 * point for P-256 and absent for Ed25519, so hashing it silently records a value no keyset can
 * contain for EC certificates. `X509Certificate(raw).publicKey.export({type: "spki"})` is the same
 * value `@gray/attest`'s keyset publishes (`tls_public_keys[].spki_sha256`), for every key type Node
 * terminates TLS with.
 */
function spkiOf(certificate: PeerCertificate): string {
  if (certificate.raw === undefined) throw new Error("the peer certificate has no DER bytes");
  const spki = new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

interface VerifyReportOptions {
  readonly nonce: string;
  readonly release: ReleaseList | null;
  readonly tlsSpkiSha256?: string;
  readonly host?: string;
  readonly nowSecs: bigint;
  readonly quoteVerifier: QuoteVerifier;
  readonly expectedRelayId?: string;
  readonly expectedRelayImage?: string;
}

function verifyReport(report: Json, options: VerifyReportOptions): Promise<AttestationVerification> {
  return verifyAttestation(report, {
    nonce: options.nonce,
    expectedComposeHashes: options.release?.composeHashes ?? [],
    expectedOsImageHashes: options.release?.osImageHashes ?? [],
    osImageMeasurements: options.release?.osImageMeasurements ?? {},
    // S11b: whether each listed image is a dstack dev image, from the list's own texts.
    ...(options.release === null
      ? {}
      : { osImageProvenance: Object.fromEntries(options.release.osImages.map((entry) => [entry.os_image_hash, osImageProvenance(entry)])) }),
    ...(options.tlsSpkiSha256 === undefined ? {} : { tlsSpkiSha256: options.tlsSpkiSha256 }),
    ...(options.host === undefined ? {} : { host: options.host }),
    ...(options.expectedRelayId === undefined ? {} : { expectedRelayId: options.expectedRelayId }),
    ...(options.expectedRelayImage === undefined ? {} : { expectedRelayImage: options.expectedRelayImage }),
    nowSecs: options.nowSecs,
    quoteVerifier: options.quoteVerifier,
  });
}

async function loadQuoteVerifier(args: ParsedArgs, nowSecs: bigint): Promise<QuoteVerifier> {
  const modulePath = args.flags.get("verifier-module");
  if (modulePath === undefined) {
    // Loaded only when a real quote is appraised: the DCAP library is the largest thing this CLI can
    // load, and a usage refusal (a missing --release-key, an unsigned list) must not pay for it. The
    // same applies to `--verifier-module`, which the tests use for a fake appraisal.
    const { dcapQuoteVerifier } = await import("./dcap.ts");
    return dcapQuoteVerifier({ pccsUrl: args.flags.get("pccs"), nowSecs: () => Number(nowSecs) });
  }
  return (await importVerifierModule(modulePath)).quoteVerifier;
}

/** What `--verifier-module` exports: `quoteVerifier`, and optionally `collateralQuoteVerifier` in `../dcap.ts`'s shape. */
interface VerifierModule {
  readonly quoteVerifier: QuoteVerifier;
  readonly collateralQuoteVerifier?: (options: { readonly collateral: (quote: Uint8Array) => unknown; readonly nowSecs?: () => number }) => QuoteVerifier;
}

async function importVerifierModule(modulePath: string): Promise<VerifierModule> {
  let imported: { readonly quoteVerifier?: unknown; readonly collateralQuoteVerifier?: unknown };
  try {
    imported = (await import(pathToFileURL(resolve(modulePath)).href)) as { readonly quoteVerifier?: unknown; readonly collateralQuoteVerifier?: unknown };
  } catch (error) {
    throw new UsageError(`cannot load quote verifier module ${modulePath}: ${messageOf(error)}`);
  }
  if (typeof imported.quoteVerifier !== "function") {
    throw new UsageError(`${modulePath} does not export a quoteVerifier function`);
  }
  return {
    quoteVerifier: imported.quoteVerifier as QuoteVerifier,
    ...(typeof imported.collateralQuoteVerifier === "function" ? { collateralQuoteVerifier: imported.collateralQuoteVerifier as NonNullable<VerifierModule["collateralQuoteVerifier"]> } : {}),
  };
}

/**
 * 1.8.0: the quote verifier for an earlier boot's stored report. With the collateral the boot stored, dcap-qvl with that
 * collateral at the boot's `checked_at` (`../dcap.ts` `collateralQuoteVerifier`); without it, the live path. With
 * `--verifier-module`, the module's `collateralQuoteVerifier` when it exports one, else its `quoteVerifier`.
 */
async function storedQuoteVerifier(args: ParsedArgs, collateral: StoredCollateral | null, checkedAt: bigint | null, nowSecs: bigint): Promise<QuoteVerifier> {
  const modulePath = args.flags.get("verifier-module");
  if (collateral === null || checkedAt === null) return loadQuoteVerifier(args, nowSecs);
  if (modulePath !== undefined) {
    const module = await importVerifierModule(modulePath);
    return module.collateralQuoteVerifier === undefined ? module.quoteVerifier : module.collateralQuoteVerifier({ collateral: () => collateral, nowSecs: () => Number(checkedAt) });
  }
  const { storedCollateralQuoteVerifier } = await import("../dcap.ts");
  return storedCollateralQuoteVerifier(collateral, checkedAt);
}

function normalizeOrigin(text: string): URL {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new UsageError(`not a URL: ${text}`);
  }
  if (url.protocol !== "https:") throw new UsageError("the origin must be https");
  if (url.username !== "" || url.password !== "") throw new UsageError("the origin must not carry credentials");
  if (url.pathname !== "/" && url.pathname !== "") throw new UsageError("the origin must not carry a path");
  if (url.search !== "" || url.hash !== "") throw new UsageError("the origin must not carry a query or fragment");
  return url;
}

/** The `--allow` list, with the line and machine member that say what made it current (D138). */
interface PinnedList {
  readonly list: ReleaseList;
  readonly line: string;
  readonly machine: JsonObject;
}

async function loadReleaseList(
  path: string,
  publicKey: Uint8Array,
  nowSecs: bigint,
  freshness: Pick<PinFlags, "freshnessPath" | "freshnessKey"> & {
    /** The built-in document of a known entry: one that cannot be fetched is absent (the list's own day), not an error. */
    readonly freshnessOptional?: boolean;
  },
): Promise<PinnedList> {
  const text = await readSource(path, "release list");
  const document = freshness.freshnessPath === null
    ? null
    : freshness.freshnessOptional === true
      ? await readSource(freshness.freshnessPath, "freshness document").catch(() => null)
      : await readSource(freshness.freshnessPath, "freshness document");
  const read = await readReleaseListText(text, {
    now: nowSecs,
    publicKey,
    ...(freshness.freshnessKey === null ? {} : { freshness: { publicKey: freshness.freshnessKey, text: document } }),
  });
  if (!read.ok) {
    const hint = read.staleness === "list_stale" ? "; a list older than a day needs --allow-freshness <its .freshness.json> --freshness-key <64 hex>" : "";
    const detail = read.code === "missing_key"
      ? "the list is signed; pass --release-key <64 hex> (Gray's release-signing public key)"
      : `${read.staleness === undefined ? "" : `${read.staleness}: `}${read.message}${hint}`;
    throw new UsageError(`invalid release list ${path}: ${read.code}: ${detail}`);
  }
  // D22: an unsigned document is refused even with a key, because the key proves nothing about it.
  if (!read.signed) {
    throw new UsageError(`invalid release list ${path}: --allow needs the signed envelope Gray publishes (D22)`);
  }
  // D20/D36: --allow asks this verifier to pin the OS image, so its entry must carry the measurements
  // that bind it to the quote's MRTD/RTMR0-2. The signed-envelope reader now refuses such a list
  // already (`missing_os_measurements`); this stays as the CLI's own rule for any list it is handed.
  for (let index = 0; index < read.list.osImages.length; index += 1) {
    if (read.list.osImages[index]!.measurements === null) {
      throw new UsageError(`invalid release list ${path}: os_images[${index}] has no mrtd/rtmr0/rtmr1/rtmr2; an OS image pinned by --allow needs its measurements (D20)`);
    }
  }
  const by = read.currentBy === "freshness" ? `the freshness document issued ${String(read.freshness?.issuedAt)}` : "its own issued_at";
  const state = read.freshness === null || read.freshness.state === "ok" || read.freshness.state === "not_configured" ? "" : `; freshness document ${read.freshness.state}`;
  const line = `release_list issued_at ${String(read.issuedAt)}, expires_at ${read.expiresAt === null ? "none" : String(read.expiresAt)}, current until ${String(read.currentUntil)} by ${by}${state}`;
  const machine: JsonObject = {
    issued_at: read.issuedAt,
    expires_at: read.expiresAt,
    current_until: read.currentUntil,
    current_by: read.currentBy,
    freshness: read.freshness?.state ?? null,
  };
  return { list: read.list, line, machine };
}

function parseUnixSeconds(text: string): bigint {
  if (!/^[0-9]+$/.test(text)) throw new UsageError("--now must be a non-negative integer (Unix seconds)");
  return BigInt(text);
}

function nowSeconds(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

function parseNonce(text: string): string {
  if (!/^[0-9a-f]{64}$/.test(text)) throw new UsageError("--nonce must be 32 bytes as 64 lower-case hex digits");
  return text;
}

function parseJsonText(text: string, what: string): Json {
  try {
    return parseStrict(text) as Json;
  } catch {
    throw new UsageError(`${what} is not JSON`);
  }
}

function parseReportText(text: string, what: string): Json {
  const parsed = parseAttestationReportText(text);
  if (!parsed.ok) throw new UsageError(`${what} is not an ACI attestation report: ${parsed.message}`);
  return parsed.value;
}

function readText(path: string, what: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    throw new UsageError(`cannot read ${what} ${path}: ${messageOf(error)}`);
  }
}

function assertFlags(args: ParsedArgs, allowed: readonly string[]): void {
  for (const name of args.flags.keys()) {
    if (!allowed.includes(name)) throw new UsageError(`unknown option --${args.spelled.get(name) ?? name}`);
  }
}

/**
 * Make one line of untrusted text safe to print: every C0/C1 control, DEL, and the Unicode line
 * separators become a literal `\uXXXX`. A signed receipt's template id, key id or body hash can
 * otherwise inject transcript lines and terminal escapes (F-12).
 */
function transcriptText(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/** A printable token: anything outside `[A-Za-z0-9_.:-]` becomes `_`. */
function safeToken(text: string): string {
  return text.replace(/[^A-Za-z0-9_.:-]/g, "_");
}

/** A check line of any of the verifiers: attestation (`VerifyCheck`) or receipt (`ReceiptCheck`, which can be `expired`). */
type CheckLine = VerifyCheck | ReceiptCheck;

function printChecks(checks: readonly CheckLine[]): void {
  for (const check of checks) {
    out(`${transcriptText(check.status.toUpperCase().padEnd(4))} ${transcriptText(check.id)}: ${transcriptText(check.detail)}\n`);
  }
}

function checkValue(check: CheckLine): JsonObject {
  return { id: transcriptText(check.id), status: check.status, detail: transcriptText(check.detail) };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The keyset a verified report binds, and the transcript of the verification that established it. */
interface AttestedKeyset {
  readonly verification: AttestationVerification;
  /** The keyset adopted from the report, or null when the report carries no valid ACI keyset. */
  readonly sealed: SealedKeyset | null;
  readonly nonce: string;
}

async function receiptCommand(args: ParsedArgs): Promise<number> {
  assertFlags(args, ["request", "origin", "lane-origin", "report", "nonce", "boot-report", "allow", "accept-os-unpinned", "release-key", "allow-freshness", "freshness-key", "response", "templates", "protocol", "ca", "now", "pccs", "verifier-module", "peers", "allow-stack", "allow-stack-freshness", "wait"]);
  if (args.positional.length !== 1) throw new UsageError("receipt needs exactly one receipt file");
  const receiptPath = args.positional[0] as string;
  const receiptText = readText(receiptPath, "receipt");
  const requestPath = requiredFlag(args, "request");
  const pins = readPinFlags(args, "receipt");
  const sharedOrigin = args.flags.has("origin") ? normalizeOrigin(requiredFlag(args, "origin")) : null;
  const reportPath = args.flags.get("report");
  // 1.8.0: --boot-report, a saved /attestation answer: the receipt's own boot, no origin attested.
  const bootReportPath = args.flags.get("boot-report");
  if ([sharedOrigin !== null, reportPath !== undefined, bootReportPath !== undefined].filter(Boolean).length !== 1) {
    throw new UsageError("receipt needs exactly one attested source: --origin <lane origin>, --report <report.json>, or --boot-report <the receipt's saved /attestation answer>");
  }
  // ER6: the replica that served is where the receipt's keyset is attested and its peer records are asked for.
  const laneOrigin = readLaneOriginFlag(args, sharedOrigin);
  const origin = laneOrigin ?? sharedOrigin;
  if (pins.allowPath === null) {
    throw new UsageError("receipt needs --allow <release-list.json>: a receipt key is only accepted from a pinned build");
  }
  if (reportPath !== undefined && !args.flags.has("nonce")) {
    throw new UsageError("receipt --report needs --nonce <64 hex>: the nonce the report was issued for");
  }
  if (bootReportPath !== undefined && args.flags.has("nonce")) {
    throw new UsageError("receipt --boot-report reads the nonce from the saved answer; --nonce is only for --report");
  }
  if (origin !== null && args.flags.has("nonce")) {
    throw new UsageError("receipt --origin generates a fresh nonce; --nonce is only for --report");
  }
  const peerFlags = readPeerFlags(args, origin, pins);
  const waitS = args.flags.has("wait") ? parseWait(args.flags.get("wait") as string) : DEFAULT_WAIT_S;
  const ca = args.flags.has("ca") ? readText(args.flags.get("ca") as string, "CA certificate") : undefined;
  const nowSecs = args.flags.has("now") ? parseUnixSeconds(args.flags.get("now") as string) : nowSeconds();
  if (pins.releaseKey === null) throw new UsageError("--allow needs --release-key <64 hex>: the signed release list Gray publishes");
  const pinned = await loadReleaseList(pins.allowPath, pins.releaseKey, nowSecs, pins);
  const release = pinned.list;
  const laneLine = laneOrigin === null || sharedOrigin === null ? "" : `lane_origin: ${laneOrigin.origin} (${LANE_ORIGIN_HEADER}, a replica of ${sharedOrigin.origin})\n`;
  const quoteVerifier = await loadQuoteVerifier(args, nowSecs);
  // The live keyset: attested at --origin, or the --report given. None with --boot-report.
  let live: AttestedKeyset | null = null;
  if (bootReportPath === undefined) {
    const attested = origin !== null
      ? await attestFromOrigin(origin, release, ca, nowSecs, quoteVerifier)
      : await attestFromReport(parseReportText(readText(reportPath as string, "attestation report"), "the attestation report"), parseNonce(args.flags.get("nonce") as string), release, nowSecs, quoteVerifier);
    if (!attestedOkFrom(attested, pins) || attested.sealed === null) {
      out(`gray-lane-verify receipt ${receiptPath}\n`);
      out(`${pinned.line}\n`);
      out(laneLine);
      printChecks(attested.verification.checks);
      printChecks([{
        id: "keyset_attestation",
        status: "fail",
        detail: attestationFailure(attested.verification, pins, attested.sealed?.digest ?? null),
      }]);
      out("VERDICT: FAIL\n");
      out(`${toJsonString(withLaneOrigin(receiptMachine({ attested, attestedOk: false, pins, receipt: null }), laneOrigin))}\n`);
      return 1;
    }
    live = attested;
  }

  const receivedBody = readBytes(requestPath, "request body");
  const responseBytes = args.flags.has("response") ? readBytes(args.flags.get("response") as string, "response body") : undefined;
  const templates = args.flags.has("templates") ? loadTemplates(args.flags.get("templates") as string) : [];
  const protocol = args.flags.has("protocol") ? parseProtocol(args.flags.get("protocol") as string) : undefined;

  // 1.8.0: a receipt of an earlier boot is verified under the keyset of the boot report the entry stored for it, read
  // from the entry or from the file --boot-report names.
  const stored = await storedFor({
    receiptText,
    live,
    bootReportPath: bootReportPath ?? null,
    origin,
    apiKey: peerFlags?.apiKey ?? apiKeyFromEnvironment(),
    ca,
    waitS,
    list: release,
    pins,
    args,
    nowSecs,
  });
  if (stored !== null && !stored.ok) {
    out(`gray-lane-verify receipt ${receiptPath}\n`);
    out(`${pinned.line}\n`);
    out(laneLine);
    printChecks(stored.checks);
    out("VERDICT: FAIL\n");
    const machine = live === null ? { command: "receipt", receipt_id: null, keyset_digest: null } : withLaneOrigin(receiptMachine({ attested: live, attestedOk: true, pins, receipt: null }), laneOrigin);
    out(`${toJsonString({ ...machine, ok: false, checks: stored.checks.map(checkValue), ...(stored.machine === null ? {} : { stored_attestation: stored.machine }) })}\n`);
    return 1;
  }
  const used = stored === null ? (live as AttestedKeyset) : stored.attested;
  const attestedOk = true;
  const keyset = used.sealed as SealedKeyset;

  // The receipt key must be the one the verified report bound: pass the sealed keyset and its digest
  // as the independent expectations (F-02, F-03). S55: and its relay image the attested boot's.
  const relayImage = attestedRelayImage(used.verification.stackBoot);
  const receipt = await verifyResponseReceiptText(receiptText, {
    receivedBody,
    templates,
    keyset,
    expectedKeysetDigest: keyset.digest,
    ...(relayImage === undefined ? {} : { expectedRelayImage: relayImage }),
    ...(responseBytes === undefined ? {} : { responseBytes }),
    ...(protocol === undefined ? {} : { protocol }),
  });

  const peers = peerFlags === null || origin === null
    ? null
    : await peerChecks({
        // What the stored report's fetch left of --wait.
        flags: { ...peerFlags, waitS: Math.max(peerFlags.waitS - (stored?.waitedS ?? 0), 0) },
        origin,
        receiptText,
        receipt,
        receivedBody,
        ...(responseBytes === undefined ? {} : { responseBytes }),
        templates,
        ca,
        nowSecs,
        quoteVerifier,
      });

  const ok = receipt.ok && (peers === null || peers.ok);
  const outcome = receiptOutcome(receipt, !peersFailed(peers), peersExpired(peers), used.verification.osPinned);
  const shown = joinedReceipt(receipt, peers);
  const note = stored === null ? "" : STORED_NOTE;
  out(`gray-lane-verify receipt ${receiptPath}\n`);
  out(`${pinned.line}\n`);
  out(laneLine);
  printChecks([{
    id: "keyset_attestation",
    status: "pass",
    detail: `${keyset.digest}; compose ${used.verification.composeHash ?? "(unpinned)"}${used.verification.osPinned ? "" : " (OS unpinned, accepted)"}${note}`,
  }]);
  if (stored !== null) {
    printChecks(stored.checks);
    for (const line of stored.lines) out(line);
  }
  printChecks(shown.checks);
  if (peers !== null) printChecks(peers.checks);
  out(`VERDICT: ${outcome.verdict}\n`);
  const machine: JsonObject = { ...withLaneOrigin(receiptMachine({ attested: used, attestedOk, pins, receipt: shown, note, extra: stored?.checks ?? [] }), laneOrigin), ...(stored === null ? {} : { stored_attestation: stored.machine }) };
  out(`${toJsonString(peers === null ? { ...machine, ...partialMachine(receipt) } : { ...machine, ok: machine.ok === true && peers.ok, peers: peersMachine(peers), ...expiredMachine(peers), ...partialMachine(receipt) })}\n`);
  return ok ? 0 : outcome.code;
}

/** 1.8.0: what the `keyset_attestation` line adds for a keyset an earlier boot's stored report shows. */
const STORED_NOTE = "; attested at boot, stored report";

/** `receipt` and `check`'s verdict for a receipt that verified, read with the other checks (`others`). */
export const NOT_END_TO_END_VERDICT = "VALID, NOT END TO END: arrived through Gray's API";
/** The exit code of `NOT_END_TO_END_VERDICT`. */
export const EXIT_NOT_END_TO_END = 3;
/** `receipt --peers` and `check`'s verdict when no check failed and a peer record had expired (1.7.1). */
export const EXPIRED_VERDICT = "EXPIRED";
/** The exit code of `EXPIRED_VERDICT`. */
export const EXIT_EXPIRED = 4;
/** `receipt` and `check`'s verdict when no check failed and the response bytes are a part of what a client that left was queued (1.7.1). */
export const PARTIAL_VERDICT = "PARTIAL";
/** The exit code of `PARTIAL_VERDICT`. */
export const EXIT_PARTIAL = 5;

/**
 * The verdict line and exit code of a receipt's checks, with whether every check but the arrival passed (`valid`): a
 * receipt whose only failed check is `client_connection` is genuine and not end to end (docs/design/one-address.md).
 * `others`: no other check failed; `expired`: a peer record was past the entry's retention. A failed check wins over an
 * expired record, so an expired record can never hide one; an expired record wins over the arrival, since part of the
 * request was not checked at all. A partial response (1.7.1) comes after a failed check and before an expired record:
 * the bytes held could not be checked against the receipt at all.
 */
function receiptOutcome(receipt: Awaited<ReturnType<typeof verifyResponseReceiptText>>, others: boolean, expired: boolean, osPinned: boolean): { readonly verdict: string; readonly code: number; readonly valid: boolean } {
  if (!others || receipt.verdict === "fail") return { verdict: "FAIL", code: 1, valid: false };
  if (receipt.verdict === "partial") return { verdict: `${PARTIAL_VERDICT}${osPinned ? "" : " (OS UNPINNED)"}`, code: EXIT_PARTIAL, valid: false };
  if (expired) return { verdict: `${EXPIRED_VERDICT}${osPinned ? "" : " (OS UNPINNED)"}`, code: EXIT_EXPIRED, valid: false };
  if (receipt.verdict === "not_end_to_end") return { verdict: `${NOT_END_TO_END_VERDICT}${osPinned ? "" : " (OS UNPINNED)"}`, code: EXIT_NOT_END_TO_END, valid: true };
  return { verdict: osPinned ? "PASS" : "PASS (OS UNPINNED)", code: 0, valid: true };
}

/** The receipt as printed: with the peer checks, its `served_attempt` passes on the attempt they tie (`withPeerTie`). */
function joinedReceipt<T extends { readonly checks: readonly ReceiptCheck[] }>(receipt: T, peers: PeerReceiptsVerification | null): T {
  return peers === null ? receipt : ({ ...receipt, checks: withPeerTie(receipt.checks, peers) } as T);
}

/** The peer checks failed: a check failed, or they did not pass for any reason but an expired record (fail-closed). */
function peersFailed(peers: PeerReceiptsVerification | null): boolean {
  return peers !== null && !peers.ok && !peersExpired(peers);
}

/** Every peer check that did not pass was skipped or an expired record, and there was one. */
function peersExpired(peers: PeerReceiptsVerification | null): boolean {
  return peers !== null && peers.expired.length > 0 && peers.checks.every((check) => check.status !== "fail");
}

/**
 * The machine output's `partial_response`, only for a `partial` verdict, so every other machine line is as it was: the
 * receipt's `served_as` and `served_attempt`, and the bytes and events (null for a buffered answer) held.
 */
function partialMachine(receipt: Awaited<ReturnType<typeof verifyResponseReceiptText>>): JsonObject {
  const partial = receipt.partialResponse;
  if (partial === null) return {};
  return {
    partial_response: {
      served_as: partial.served_as,
      served_attempt: safeToken(partial.served_attempt),
      bytes_received: BigInt(partial.bytes_received),
      events_received: partial.events_received === null ? null : BigInt(partial.events_received),
    },
  };
}

/** The machine output's `expired_peers`, only when a record had expired, so every other machine line is as it was. */
function expiredMachine(peers: PeerReceiptsVerification | null): JsonObject {
  return peers === null || peers.expired.length === 0 ? {} : { expired_peers: peers.expired.map(safeToken) };
}

/**
 * `--lane-origin`: the `x-gray-lane-origin` value of the response (ER6), read by the rule of `lane-origin.ts`. Only
 * with `--origin`, the shared name it must be a replica of. A refused value is an error that says why, and nothing is
 * fetched: falling back to `--origin` would ask a replica that may not hold the receipt, and hide why.
 */
function readLaneOriginFlag(args: ParsedArgs, sharedOrigin: URL | null): URL | null {
  const value = args.flags.get("lane-origin");
  if (value === undefined) return null;
  if (sharedOrigin === null) throw new UsageError("--lane-origin needs --origin <lane origin>: it names the replica of that origin that served");
  const read = readLaneOrigin(value, sharedOrigin);
  if (!read.ok) throw new Error(`--lane-origin (${LANE_ORIGIN_HEADER}) refused: ${read.reason}; nothing was fetched from it or from any other origin`);
  return read.origin;
}

/** The machine output names the replica asked, when one was (`--lane-origin`); otherwise it is as before. */
function withLaneOrigin(machine: JsonObject, laneOrigin: URL | null): JsonObject {
  return laneOrigin === null ? machine : { ...machine, lane_origin: laneOrigin.origin };
}

/** `--peers` and its stack list: checked before anything is fetched. */
interface PeerFlags {
  readonly apiKey: string;
  readonly list: PeerReleaseList;
  /** How long, in seconds of `Retry-After`, the records may still be asked again (`--wait`, or what `check` left of it). */
  readonly waitS: number;
}

function readPeerFlags(args: ParsedArgs, origin: URL | null, pins: PinFlags): PeerFlags | null {
  const stackPath = args.flags.get("allow-stack");
  const stackFreshness = args.flags.get("allow-stack-freshness");
  if (!args.flags.has("peers")) {
    if (stackPath !== undefined || stackFreshness !== undefined) throw new UsageError("--allow-stack and --allow-stack-freshness are only meaningful with --peers");
    // 1.8.0: with --origin, --wait also bounds the asks for an earlier boot's stored report.
    if (args.flags.has("wait") && origin === null) throw new UsageError("--wait is only meaningful with --origin: it bounds the asks to the entry for an earlier boot's stored report and, with --peers, a provider VM's records");
    return null;
  }
  if (origin === null) throw new UsageError("receipt --peers needs --origin <lane origin>: the entry serves each peer attempt's records for the receipt");
  if (stackPath === undefined) throw new UsageError("receipt --peers needs --allow-stack <stack release-list.json>: Gray's signed list of stack releases");
  if (pins.releaseKey === null) throw new UsageError("--allow-stack needs --release-key <64 hex>");
  if (stackFreshness !== undefined && pins.freshnessKey === null) throw new UsageError("--allow-stack-freshness needs --freshness-key <64 hex>");
  // The key that made the request reads the receipt's records (ACI §7.6). Never a flag: a command line is visible to other processes.
  const apiKey = process.env.GRAY_API_KEY;
  if (apiKey === undefined || apiKey === "") throw new UsageError("receipt --peers needs the key that made the request in the environment: GRAY_API_KEY");
  if (!/^[\x21-\x7e]{1,4096}$/.test(apiKey)) throw new UsageError("GRAY_API_KEY is not an API key (printable ASCII without spaces)");
  const freshnessFrom = stackFreshnessSource(stackPath, stackFreshness ?? null, pins.freshnessKey);
  let freshnessText: string | null = null;
  if (freshnessFrom !== null) {
    try {
      freshnessText = readText(freshnessFrom.source, "stack freshness document");
    } catch (error) {
      if (!freshnessFrom.optional) throw error;
    }
  }
  const list: PeerReleaseList = {
    text: readText(stackPath, "stack release list"),
    publicKey: pins.releaseKey,
    ...(freshnessFrom === null || pins.freshnessKey === null ? {} : { freshness: { text: freshnessText, publicKey: pins.freshnessKey } }),
  };
  const waitS = args.flags.has("wait") ? parseWait(args.flags.get("wait") as string) : DEFAULT_WAIT_S;
  return { apiKey, list, waitS };
}

/**
 * Where the stack list's freshness document is read from (D135, D137). With no freshness key pinned there is none, and
 * the list is current for a day after its `issued_at`. `--allow-stack-freshness` names it, and one that cannot be read
 * is an error. Without that flag it is the document beside the list (`releaseFreshnessLocation`: `.json` replaced by
 * `.freshness.json`, where Gray's signer writes it), as for the built-in lists; one that cannot be read counts as absent,
 * so the list keeps only its own day and an older list still fails.
 */
function stackFreshnessSource(list: string, given: string | null, freshnessKey: Uint8Array | null): { readonly source: string; readonly optional: boolean } | null {
  if (freshnessKey === null) return null;
  return given !== null ? { source: given, optional: false } : { source: releaseFreshnessLocation(list), optional: true };
}

/** The largest `/peers/{n}` answer read: a report (MAX_REPORT_BYTES) and an inner receipt (at most 64 KiB) with room. */
const MAX_PEER_ANSWER_BYTES = MAX_REPORT_BYTES + 256 * 1024;

/**
 * `--peers`: each peer attempt's records fetched from the entry and checked (`verifyPeerReceipts`). Only after the outer
 * receipt verified: its peer events are what the records are held to. A fetch that fails is a FAIL line, not an error.
 */
async function peerChecks(input: {
  readonly flags: PeerFlags;
  readonly origin: URL;
  readonly receiptText: string;
  readonly receipt: Awaited<ReturnType<typeof verifyResponseReceiptText>>;
  readonly receivedBody: Uint8Array;
  readonly responseBytes?: Uint8Array;
  readonly templates: readonly TemplateText[];
  readonly ca: string | undefined;
  readonly nowSecs: bigint;
  readonly quoteVerifier: QuoteVerifier;
}): Promise<PeerReceiptsVerification> {
  const parsed = parseReceiptText(input.receiptText);
  if (input.receipt.verdict === "fail" || !parsed.ok || input.receipt.receiptId === null) {
    return { ok: false, checks: [{ id: "peers", status: "skip", detail: "not checked: the outer receipt did not verify" }], peers: [], expired: [], tied: null };
  }
  const outer = parsed.value;
  const answers = new Map<string, PeerAnswer | PeerAnswerError>();
  const sleep = net.sleep ?? (NODE_NET.sleep as NonNullable<CliNet["sleep"]>);
  // One --wait for every record: the seconds slept for one are gone for the next.
  let waitedS = 0;
  for (const n of peerNumbersToFetch(outer)) {
    const url = new URL(`/v1/aci/receipts/${encodeURIComponent(input.receipt.receiptId)}/peers/${n}`, input.origin);
    let fetched: FetchedText;
    let waitedHereS = 0;
    try {
      for (;;) {
        fetched = await net.getWithKey(url, input.flags.apiKey, input.ca, MAX_PEER_ANSWER_BYTES);
        // The stack VM has not signed its receipt yet (receipt-route.ts), or the entry could not reach it, or (1.8.0) the
        // entry's receipt store did not answer: ask again. A receipt that does not match (peer_receipt_mismatch), and
        // every other answer, is taken as it is.
        if (!askAgain(fetched)) break;
        const leftS = input.flags.waitS - waitedS;
        if (leftS <= 0) break;
        const retryS = Math.min(retryAfterSeconds(fetched.headers?.["retry-after"]), leftS);
        await sleep(retryS * 1000);
        waitedS += retryS;
        waitedHereS += retryS;
      }
    } catch (error) {
      answers.set(n.toString(), { error: `cannot fetch ${url.pathname}: ${messageOf(error)}` });
      continue;
    }
    if (fetched.status !== 200) {
      // The status and the exact code: verifyPeerReceipts reads a 404 receipt_not_found past the retention as expired.
      const code = exactErrorCode(fetched.text);
      const still = askAgain(fetched) ? `, still after ${String(waitedHereS)} s: ask again later, or give --wait more seconds` : "";
      answers.set(n.toString(), { error: `${url.pathname} answered ${fetched.status}${errorCodeOf(fetched.text)}${still}`, status: fetched.status, code });
      continue;
    }
    const read = readPeerAnswerText(fetched.text);
    answers.set(n.toString(), read.ok ? read.answer : { error: `${url.pathname} is not a peer record: ${read.message}` });
  }
  return verifyPeerReceipts({
    outer,
    receivedBody: input.receivedBody,
    ...(input.responseBytes === undefined ? {} : { responseBytes: input.responseBytes }),
    templates: input.templates,
    releaseList: input.flags.list,
    quoteVerifier: input.quoteVerifier,
    nowSecs: input.nowSecs,
    answers,
  });
}

/** The entry's 502 for a record of a stack VM it could not get yet (receipt-route.ts), an answer asked again. */
const PEER_RECEIPT_UNAVAILABLE = "peer_receipt_unavailable";

/** A `/peers/<n>` answer asked again within --wait: 502 peer_receipt_unavailable, or 503 receipt_lookup_unavailable. */
function askAgain(fetched: FetchedText): boolean {
  const code = exactErrorCode(fetched.text);
  return (fetched.status === 502 && code === PEER_RECEIPT_UNAVAILABLE) || (fetched.status === 503 && code === RECEIPT_LOOKUP_UNAVAILABLE);
}

/** The `error.code` string of an ACI error body (`{error: {code}}`) exactly as sent, or null. */
function exactErrorCode(text: string): string | null {
  try {
    const code = get(get(parseStrict(text), "error"), "code");
    return typeof code === "string" ? code : null;
  } catch {
    return null;
  }
}

/** ` (<code>)` of an ACI error body (`{error: {code}}`), or nothing. */
function errorCodeOf(text: string): string {
  try {
    const code = get(get(parseStrict(text), "error"), "code");
    return typeof code === "string" ? ` (${safeToken(code)})` : "";
  } catch {
    return "";
  }
}

/** One GET over TLS with the customer's key as a bearer credential (never in the URL), the body read up to `maxBytes`. */
function httpsWithKey(url: URL, apiKey: string, ca: string | undefined, maxBytes: number): Promise<FetchedText> {
  return httpsGet(url, apiKey, ca, maxBytes);
}

/** One GET over TLS, with the customer's key as a bearer credential when given; status, headers and body up to `maxBytes`. */
function httpsGet(url: URL, apiKey: string | undefined, ca: string | undefined, maxBytes: number): Promise<FetchedText> {
  return new Promise((resolvePromise, rejectPromise) => {
    const request = httpsRequest(
      url.toString(),
      {
        method: "GET",
        ...(ca === undefined ? {} : { ca }),
        headers: {
          accept: "application/json",
          ...(apiKey === undefined ? {} : { authorization: `Bearer ${apiKey}` }),
          "user-agent": `gray-lane-verify/${VERSION}`,
        },
        timeout: 20_000,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            response.destroy(new Error(`the answer is larger than ${maxBytes} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", rejectPromise);
        response.on("end", () => {
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(response.headers)) {
            if (typeof value === "string") headers[name.toLowerCase()] = value;
            else if (Array.isArray(value)) headers[name.toLowerCase()] = value.join(", ");
          }
          resolvePromise({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8"), headers });
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("the request timed out")));
    request.on("error", rejectPromise);
    request.end();
  });
}

function peersMachine(peers: PeerReceiptsVerification): Json {
  const nullableToken = (text: string | null): string | null => (text === null ? null : safeToken(text));
  return peers.peers.map((peer) => ({
    n: safeToken(peer.n),
    host: nullableToken(peer.host),
    relay_id: nullableToken(peer.relay_id),
    relay_image: peer.relay_image,
    keyset_digest: nullableToken(peer.keyset_digest),
    compose_hash: nullableToken(peer.compose_hash),
    inner_receipt_id: nullableToken(peer.inner_receipt_id),
    inner_receipt_sha256: nullableToken(peer.inner_receipt_sha256),
    stack: peer.stack === null ? null : stackMachine(peer.stack),
  })) as unknown as Json;
}

async function attestFromOrigin(origin: URL, release: ReleaseList, ca: string | undefined, nowSecs: bigint, quoteVerifier: QuoteVerifier): Promise<AttestedKeyset> {
  const nonce = randomBytes(32).toString("hex");
  let fetched: FetchedReport;
  try {
    fetched = await fetchAttestation(origin, nonce, ca);
  } catch (error) {
    throw new UsageError(`cannot fetch ${origin.origin}/v1/aci/attestation: ${messageOf(error)}`);
  }
  const report = parseReportText(fetched.text, "the attestation report");
  const sealed = sealedFromReport(report);
  const verification = await verifyReport(report, {
    nonce,
    release,
    tlsSpkiSha256: fetched.spkiSha256,
    host: origin.hostname,
    nowSecs,
    quoteVerifier,
  });
  return { verification, sealed, nonce };
}

async function attestFromReport(report: Json, nonce: string, release: ReleaseList, nowSecs: bigint, quoteVerifier: QuoteVerifier): Promise<AttestedKeyset> {
  const sealed = sealedFromReport(report);
  const verification = await verifyReport(report, { nonce, release, nowSecs, quoteVerifier });
  return { verification, sealed, nonce };
}

function sealedFromReport(report: Json): SealedKeyset | null {
  const value = reportKeysetValue(report);
  if (value === undefined) return null;
  return adoptKeyset(value);
}

// ---------------------------------------------------------------------------------------------------------------
// 1.8.0: a receipt of an earlier boot, verified with the boot report the entry stored for it
// ---------------------------------------------------------------------------------------------------------------

/**
 * The earlier boot's report a receipt is verified with: the file `--boot-report` names (the receipt's own boot,
 * whatever runs now), else, when the receipt names a keyset other than the live one, the entry's `/attestation` at
 * `origin`. Null when neither applies: the receipt is the live boot's, or `--report` attested it.
 */
async function storedFor(input: {
  readonly receiptText: string;
  readonly live: AttestedKeyset | null;
  readonly bootReportPath: string | null;
  readonly origin: URL | null;
  readonly apiKey: string | null;
  readonly ca: string | undefined;
  readonly waitS: number;
  readonly list: ReleaseList;
  readonly pins: PinFlags;
  readonly args: ParsedArgs;
  readonly nowSecs: bigint;
}): Promise<StoredBoot | null> {
  const common = { list: input.list, pins: input.pins, args: input.args, nowSecs: input.nowSecs };
  if (input.bootReportPath !== null) {
    const text = readText(input.bootReportPath, "boot report");
    const older = receiptBootOf(input.receiptText);
    if (older === null) {
      const detail = "the receipt does not read as a receipt with an id, a keyset digest and a served_at, so no boot report can be matched to it";
      return { ok: false, checks: [{ id: "stored_attestation", status: "fail", detail }], lines: [], machine: null, waitedS: 0 };
    }
    return storedBootAttestation({ source: { kind: "file", path: input.bootReportPath, text }, older, ...common });
  }
  const liveDigest = input.live?.sealed?.digest;
  if (input.origin === null || liveDigest === undefined) return null;
  const older = olderBootOf(input.receiptText, liveDigest);
  if (older === null) return null;
  return storedBootAttestation({ source: { kind: "fetch", origin: input.origin, liveDigest, apiKey: input.apiKey, ca: input.ca, waitS: input.waitS }, older, ...common });
}

/** The boot a receipt names: its id, keyset, signed time and signed retention. */
interface OlderBoot {
  readonly receiptId: string;
  readonly keysetDigest: string;
  readonly servedAt: bigint;
  /** The receipt's signed `retention_seconds`, null when it carries none (an hour in the entry's memory). */
  readonly retentionSeconds: bigint | null;
}

/** The receipt's id, keyset, `served_at` and `retention_seconds`; null when it does not read as a receipt with them. */
function receiptBootOf(receiptText: string): OlderBoot | null {
  const parsed = parseReceiptText(receiptText);
  if (!parsed.ok) return null;
  const digest = get(parsed.value, "workload_keyset_digest");
  const receiptId = get(parsed.value, "receipt_id");
  const servedAt = get(parsed.value, "served_at");
  const retention = get(parsed.value, "retention_seconds");
  if (typeof digest !== "string" || typeof receiptId !== "string" || !RECEIPT_ID_FORM.test(receiptId) || typeof servedAt !== "bigint" || servedAt < 0n) return null;
  return { receiptId, keysetDigest: digest, servedAt, retentionSeconds: typeof retention === "bigint" ? retention : null };
}

/** The receipt's boot when it names a keyset other than `liveDigest`; null otherwise. */
function olderBootOf(receiptText: string, liveDigest: string): OlderBoot | null {
  const boot = receiptBootOf(receiptText);
  return boot === null || boot.keysetDigest === liveDigest ? null : boot;
}

/** Where an earlier boot's report comes from: the entry's `/attestation` (online) or a saved answer (`--boot-report`). */
type StoredSource =
  | { readonly kind: "fetch"; readonly origin: URL; readonly liveDigest: string; readonly apiKey: string | null; readonly ca: string | undefined; readonly waitS: number }
  | { readonly kind: "file"; readonly path: string; readonly text: string };

/** The longest a boot's stored collateral may have been checked before the receipt was served: a missed daily refresh. */
const STORED_COLLATERAL_MAX_AGE_SECONDS = 2n * 86_400n;

/**
 * Item (a) and (b) of the stored collateral's time (PR #1129 review), with A = `attested_at`, C =
 * `collateral_check.checked_at`, S = the receipt's `served_at`, N = now and the 300 s clock margin:
 *
 *   (a) A - 300 <= C <= N + 300, and (b) C >= S - 2 days - 300.
 *
 * Why. The collateral is Intel-signed (TCB info, QE identity, CRLs under Intel's root), so no one can forge it; what
 * an entry, or anyone serving `/attestation`, can do is choose an older genuine one, from before Intel revoked the
 * platform or downgraded its TCB, and date the check accordingly. dcap-qvl takes C as its clock, so a backdated C
 * would make that old collateral current again. The entry refreshes the boot's collateral daily (same report, new
 * collateral and C), so (b) ties C to at most two days before the receipt was served, one missed refresh tolerated,
 * and (a) keeps C within the boot's life up to now. Online, `retention_window` ((c), S >= N - (retention_seconds +
 * 3 900)) ties S to the receipt's signed retention, so together a platform revocation older than the retention plus
 * two days and the margins cannot be hidden by backdating. A saved report (`--boot-report`) is checked later by
 * design, so (c) does not apply there and the transcript says so; (a) and (b) still do.
 */
function collateralWindowCheck(attestedAt: bigint, checkedAt: bigint, servedAt: bigint, nowSecs: bigint): CheckLine {
  const margin = RECEIPT_CLOCK_MARGIN_SECONDS;
  const earliest = servedAt - STORED_COLLATERAL_MAX_AGE_SECONDS - margin;
  const at = `collateral checked at ${String(checkedAt)}`;
  if (checkedAt < attestedAt - margin) return { id: "collateral_window", status: "fail", detail: `${at}, before the boot was attested at ${String(attestedAt)} (with ${String(margin)} s for clocks)` };
  if (checkedAt > nowSecs + margin) return { id: "collateral_window", status: "fail", detail: `${at}, after now ${String(nowSecs)} (with ${String(margin)} s for clocks)` };
  if (checkedAt < earliest) {
    return {
      id: "collateral_window",
      status: "fail",
      detail: `${at}, more than two days before the receipt was served at ${String(servedAt)} (the earliest taken is ${String(earliest)}; the entry refreshes the collateral daily): an older collateral may hide a later revocation`,
    };
  }
  return { id: "collateral_window", status: "pass", detail: `${at}: after the boot was attested at ${String(attestedAt)}, not after now, and at most two days before the receipt was served at ${String(servedAt)}` };
}

/** (c), online only: the receipt was served within its signed retention of now. */
/**
 * The most of a receipt's signed `retention_seconds` the online stored-boot window counts: the entry's own 30 days
 * (docs/design/persisted-receipts.md section 3). The member is signed by the receipt's own keyset, so a hostile origin on
 * a since-revoked platform could sign 2^32 - 1 (136 years) and backdate `served_at` and the collateral's check to before
 * the revocation; capped, the window ends 30 days and 3 900 s after serving whatever the receipt says.
 */
export const MAX_STORED_RETENTION_SECONDS = 2_592_000n;

function retentionWindowCheck(older: OlderBoot, source: StoredSource, nowSecs: bigint): CheckLine {
  if (source.kind === "file") {
    return { id: "retention_window", status: "skip", detail: `not checked: the boot report is a saved file (--boot-report ${transcriptText(source.path)}), checked after the entry's retention by design` };
  }
  const signed = older.retentionSeconds;
  const capped = signed !== null && signed > MAX_STORED_RETENTION_SECONDS;
  const retention = signed === null ? ENTRY_RECEIPT_RETENTION_SECONDS : capped ? MAX_STORED_RETENTION_SECONDS : signed;
  const bound = peerRecordRetentionBound(retention);
  const earliest = nowSecs - bound;
  const said = signed === null
    ? `${String(retention)} s (no retention_seconds signed: an hour)`
    : capped
      ? `${String(retention)} s (its signed retention_seconds ${String(signed)}, counted at most ${String(MAX_STORED_RETENTION_SECONDS)} s)`
      : `${String(retention)} s (its signed retention_seconds)`;
  return older.servedAt >= earliest
    ? { id: "retention_window", status: "pass", detail: `served at ${String(older.servedAt)}, within ${said} + ${String(PEER_RECORD_RETENTION_MARGIN_SECONDS)} s of now ${String(nowSecs)}` }
    : { id: "retention_window", status: "fail", detail: `served at ${String(older.servedAt)}, before ${String(earliest)}: more than ${said} + ${String(PEER_RECORD_RETENTION_MARGIN_SECONDS)} s before now ${String(nowSecs)}; check it with its saved /attestation answer (--boot-report)` };
}

/** The entry's 503 when its receipt store (R2, through the bridge) did not answer (persisted-receipts.md section 6). */
const RECEIPT_LOOKUP_UNAVAILABLE = "receipt_lookup_unavailable";
/** The largest `/attestation` answer read: a report and its collateral (about 20 KB), with room. */
const MAX_STORED_ANSWER_BYTES = MAX_REPORT_BYTES + 256 * 1024;

type StoredBoot =
  | {
    readonly ok: true;
    /** The stored report's verification and the keyset it binds: what the receipt is verified under. */
    readonly attested: AttestedKeyset;
    readonly checks: readonly CheckLine[];
    readonly lines: readonly string[];
    readonly machine: JsonObject;
    readonly attestedAt: bigint;
    readonly waitedS: number;
  }
  | { readonly ok: false; readonly checks: readonly CheckLine[]; readonly lines: readonly string[]; readonly machine: JsonObject | null; readonly waitedS: number };

/**
 * `GET <origin>/v1/aci/receipts/<id>/attestation` with the key that made the request, asked again after a
 * `503 receipt_lookup_unavailable`'s `Retry-After` while `waitS` lasts.
 */
async function fetchStoredAttestation(url: URL, apiKey: string, ca: string | undefined, waitS: number): Promise<{ readonly ok: true; readonly text: string; readonly waitedS: number } | { readonly ok: false; readonly detail: string; readonly waitedS: number }> {
  const sleep = net.sleep ?? (NODE_NET.sleep as NonNullable<CliNet["sleep"]>);
  let waitedS = 0;
  for (;;) {
    let fetched: FetchedText;
    try {
      fetched = await net.getWithKey(url, apiKey, ca, MAX_STORED_ANSWER_BYTES);
    } catch (error) {
      return { ok: false, detail: `cannot fetch ${url.pathname}: ${messageOf(error)}`, waitedS };
    }
    if (fetched.status === 200) return { ok: true, text: fetched.text, waitedS };
    if (fetched.status === 503 && exactErrorCode(fetched.text) === RECEIPT_LOOKUP_UNAVAILABLE) {
      const leftS = waitS - waitedS;
      if (leftS > 0) {
        const retryS = Math.min(retryAfterSeconds(fetched.headers?.["retry-after"]), leftS);
        await sleep(retryS * 1000);
        waitedS += retryS;
        continue;
      }
      return { ok: false, detail: `${url.pathname} still answers 503 ${RECEIPT_LOOKUP_UNAVAILABLE} after ${String(waitedS)} s: the entry's receipt store did not answer; ask again later, or give --wait more seconds`, waitedS };
    }
    return { ok: false, detail: `${url.pathname} answered ${String(fetched.status)}${errorCodeOf(fetched.text)}`, waitedS };
  }
}

/**
 * Whether the release list at the receipt's `served_at` takes the stored report's compose (`releaseListAt`): a current
 * release, or a superseded one whose window covers `served_at`. A line for the transcript, null without a compose.
 */
function releaseAtCheck(list: ReleaseList, composeHash: string | null, servedAt: bigint): { readonly check: CheckLine; readonly supersededAt: bigint | null } | null {
  if (composeHash === null) return null;
  const hash = safeToken(composeHash);
  if (list.composeHashes.includes(composeHash)) {
    return { check: { id: "release_at", status: "pass", detail: `compose ${hash} is a current release of the list` }, supersededAt: null };
  }
  const superseded = (list.superseded ?? []).find((entry) => entry.compose_hash === composeHash);
  if (superseded === undefined) {
    return { check: { id: "release_at", status: "fail", detail: `compose ${hash} is not in the release list, current or superseded` }, supersededAt: null };
  }
  const until = superseded.superseded_at + RELEASE_LIST_DEFAULT_MAX_FUTURE_SECONDS;
  const window = `superseded at ${String(superseded.superseded_at)}, accepted until ${String(until)}`;
  return servedAt <= until
    ? { check: { id: "release_at", status: "pass", detail: `compose ${hash} accepted at the receipt's served_at ${String(servedAt)}: ${window}` }, supersededAt: superseded.superseded_at }
    : { check: { id: "release_at", status: "fail", detail: `compose ${hash} not accepted at the receipt's served_at ${String(servedAt)}: ${window}` }, supersededAt: superseded.superseded_at };
}

/**
 * The receipt's keyset from the boot report the entry stored for the earlier boot that signed it (the module's
 * comment): fetched, its receipt id, keyset digest and derived nonce checked, then verified like `--report --nonce`
 * with the stored collateral at its `checked_at` (or live collateral), the keyset's `not_after` at `served_at`, and the
 * compose taken from the release list at `served_at`.
 */
async function storedBootAttestation(input: {
  readonly source: StoredSource;
  readonly older: OlderBoot;
  readonly list: ReleaseList;
  readonly pins: PinFlags;
  readonly args: ParsedArgs;
  readonly nowSecs: bigint;
}): Promise<StoredBoot> {
  const { older, source } = input;
  const why = source.kind === "fetch"
    ? `the receipt names keyset ${safeToken(older.keysetDigest)}, not the one ${source.origin.origin} attests now (${source.liveDigest}): an earlier boot signed it`
    : `the receipt names keyset ${safeToken(older.keysetDigest)}, checked against the boot report saved in ${transcriptText(source.path)} (--boot-report)`;
  const failed = (detail: string, waitedS: number, checks: readonly CheckLine[] = [], machine: JsonObject | null = null): StoredBoot =>
    ({ ok: false, checks: [...checks, { id: "stored_attestation", status: "fail", detail }], lines: [], machine, waitedS });
  let text: string;
  let where: string;
  let waitedS = 0;
  if (source.kind === "fetch") {
    if (source.apiKey === null) return failed(`${why}, and that boot's stored report is read with the key that made the request: set GRAY_API_KEY`, 0);
    const url = new URL(`/v1/aci/receipts/${encodeURIComponent(older.receiptId)}/attestation`, source.origin);
    const fetched = await fetchStoredAttestation(url, source.apiKey, source.ca, source.waitS);
    waitedS = fetched.waitedS;
    if (!fetched.ok) return failed(`${why}; its stored report: ${fetched.detail}`, waitedS);
    text = fetched.text;
    where = url.pathname;
  } else {
    text = source.text;
    where = transcriptText(source.path);
  }
  const fetched = { waitedS };
  const read = readStoredAttestationText(text);
  if (!read.ok) return failed(`${why}; ${where} is not a stored boot report: ${read.message}`, fetched.waitedS);
  const answer: StoredAttestation = read.answer;
  if (answer.receipt_id !== older.receiptId) return failed(`${why}; the stored report answered is for receipt ${answer.receipt_id}`, fetched.waitedS);
  if (answer.keyset_digest !== older.keysetDigest) return failed(`${why}; the stored report is for keyset ${answer.keyset_digest}, not the receipt's`, fetched.waitedS);
  const derived = bootReportNonce(answer.keyset_digest);
  if (answer.nonce !== derived) return failed(`${why}; the stored report's nonce ${answer.nonce} is not ${derived}, the one derived from its keyset digest`, fetched.waitedS);

  const checkedAt = answer.collateral_check?.checked_at ?? null;
  // The collateral's time and the receipt's, before the collateral is used (collateralWindowCheck says why).
  const timeChecks: CheckLine[] = [
    answer.collateral === null || checkedAt === null
      ? { id: "collateral_window", status: "skip", detail: "no collateral stored with the report: the quote is verified with live collateral now, so no stored time is bound" }
      : collateralWindowCheck(answer.attested_at, checkedAt, older.servedAt, input.nowSecs),
    retentionWindowCheck(older, source, input.nowSecs),
  ];
  const timeFailure = timeChecks.find((check) => check.status === "fail");
  if (timeFailure !== undefined) return failed(`${why}; the stored report's times are not accepted (${timeFailure.id})`, fetched.waitedS, timeChecks);
  const verifier = await storedQuoteVerifier(input.args, answer.collateral, checkedAt, input.nowSecs);
  let appraisal: QuoteAppraisal | null = null;
  const quoteVerifier: QuoteVerifier = async (quote) => {
    appraisal = await verifier(quote);
    return appraisal;
  };
  const release = releaseListAt(input.list, older.servedAt);
  const sealed = sealedFromReport(answer.report);
  // The keyset's not_after is held to the time the receipt was signed, not to now.
  const verification = await verifyReport(answer.report, { nonce: answer.nonce, release, nowSecs: older.servedAt, quoteVerifier });
  const attested: AttestedKeyset = { verification, sealed, nonce: answer.nonce };
  const window = releaseAtCheck(input.list, verification.composeHash, older.servedAt);
  const tcbStatus = (appraisal as QuoteAppraisal | null)?.tcbStatus ?? null;
  const collateral = answer.collateral === null ? "live" : "stored";
  const issueDate = answer.collateral === null ? null : collateralIssueDate(answer.collateral);
  const machine: JsonObject = {
    source: source.kind === "fetch" ? "fetched" : "file",
    keyset_digest: answer.keyset_digest,
    nonce: answer.nonce,
    attested_at: answer.attested_at,
    served_at: older.servedAt,
    collateral,
    collateral_issue_date: issueDate === null ? null : transcriptText(issueDate),
    checked_at: checkedAt,
    tcb_status: tcbStatus === null ? null : safeToken(tcbStatus),
    compose_hash: verification.composeHash,
    superseded_at: window?.supersededAt ?? null,
  };
  const windowChecks = [...timeChecks, ...(window === null ? [] : [window.check])];
  if (!attestedOkFrom(attested, input.pins) || sealed === null || sealed.digest !== older.keysetDigest || window?.check.status === "fail") {
    const stored = verification.checks.filter((check) => check.status !== "pass").map((check) => ({ ...check, id: `stored:${check.id}` }));
    const detail = sealed !== null && sealed.digest !== older.keysetDigest && verification.ok
      ? `the stored report binds keyset ${sealed.digest}, not the receipt's`
      : `the stored boot report did not verify: ${attestationFailure(verification, input.pins, sealed?.digest ?? null)}`;
    return failed(`${why}; ${detail}`, fetched.waitedS, [...stored, ...windowChecks], machine);
  }
  const status = tcbStatus === null ? "(none reported)" : safeToken(tcbStatus);
  const lines = [
    `stored_report: attested at boot, stored report: ${why}. ${source.kind === "fetch" ? "The entry stored" : "The file holds"} that boot's report, attested at ${String(answer.attested_at)} with nonce ${answer.nonce}, `
      + "derived from the keyset digest: no verifier chose it, so it shows the keyset came from the measured VM, not that the VM runs now\n",
    answer.collateral === null
      ? `collateral: none stored with the report: the quote was verified with live collateral now: TCB ${status}\n`
      : `collateral: stored with the report, issued ${issueDate === null ? "(no issueDate)" : transcriptText(issueDate)}, the quote verified with it at ${String(checkedAt)}: TCB ${status}\n`,
  ];
  return { ok: true, attested, checks: windowChecks, lines, machine, attestedAt: answer.attested_at, waitedS: fetched.waitedS };
}

/** Whether the attested keyset came from a fully verified report under the requested pinning. */
function attestedOkFrom(attested: AttestedKeyset, pins: PinFlags): boolean {
  const verification = attested.verification;
  return (
    verification.ok &&
    verification.composePinned &&
    (verification.osPinned || pins.acceptOsUnpinned) &&
    attested.sealed !== null &&
    verification.keysetDigest !== null &&
    verification.keysetDigest === attested.sealed.digest
  );
}

function attestationFailure(verification: AttestationVerification, pins: PinFlags, sealedDigest: string | null): string {
  if (!verification.ok) {
    const failed = verification.checks.filter((check) => check.status === "fail").map((check) => check.id);
    return `the report did not verify (${failed.length === 0 ? "no failing check reported" : failed.join(", ")})`;
  }
  if (!verification.composePinned) return "the report's compose hash is not pinned by a release list";
  if (!verification.osPinned && !pins.acceptOsUnpinned) return "the release list pins no OS image; pass --accept-os-unpinned to accept";
  if (sealedDigest === null) return "the report carries no valid ACI workload keyset";
  return `the verified keyset digest ${String(verification.keysetDigest)} does not match the report keyset ${sealedDigest}`;
}

function receiptMachine(input: {
  readonly attested: AttestedKeyset;
  readonly attestedOk: boolean;
  readonly pins: PinFlags;
  readonly receipt: Awaited<ReturnType<typeof verifyResponseReceiptText>> | null;
  /** 1.8.0: STORED_NOTE for a keyset an earlier boot's stored report shows, and its `release_at` check. */
  readonly note?: string;
  readonly extra?: readonly CheckLine[];
}): JsonObject {
  const verification = input.attested.verification;
  const receipt = input.receipt;
  const checks: CheckLine[] = [
    {
      id: "keyset_attestation",
      status: input.attestedOk ? "pass" : "fail",
      detail: input.attestedOk
        ? `${input.attested.sealed?.digest ?? "(no keyset)"}; compose ${verification.composeHash ?? "(unpinned)"}${verification.osPinned ? "" : " (OS unpinned, accepted)"}${input.note ?? ""}`
        : attestationFailure(verification, input.pins, input.attested.sealed?.digest ?? null),
    },
    ...(input.extra ?? []),
    ...(receipt?.checks ?? []),
  ];
  return {
    command: "receipt",
    ok: input.attestedOk && receipt !== null && receipt.ok,
    receipt_id: receipt?.receiptId ?? null,
    keyset_digest: receipt?.keysetDigest ?? input.attested.sealed?.digest ?? null,
    protocol: receipt?.protocol ?? null,
    relay_policy: receipt?.relayPolicy ?? "absent",
    received_body_sha256: receipt?.receivedBodyHash ?? null,
    forwarded_body_sha256: receipt?.forwardedBodyHash ?? null,
    response_body_sha256: receipt?.responseBodyHash ?? null,
    relay_image: receipt?.relayImage ?? null,
    // docs/design/one-address.md: only on a receipt that names it, so every other machine line is as it was.
    ...(receipt?.arrival === null || receipt?.arrival === undefined ? {} : { arrival: safeToken(receipt.arrival) }),
    // A translated request (`request.translated`): only on a receipt that names one, as `arrival`. The APIs are a closed
    // vocabulary and the dropped names lower-case identifiers (the event's schema).
    ...(receipt?.translation === null || receipt?.translation === undefined
      ? {}
      : {
          translation: {
            from: receipt.translation.from,
            to: receipt.translation.to,
            dropped: [...receipt.translation.dropped],
            output_cap: receipt.translation.output_cap,
          },
        }),
    appended: (receipt?.appended ?? []).map((append) => ({
      // Template ids are attacker-controlled signed data; a token-only form keeps a fake verdict
      // out of the machine JSON as well as out of the printed transcript.
      template_id: safeToken(append.template_id),
      position: safeToken(append.position),
      text_sha256: safeToken(append.text_sha256),
    })),
    // Gray's declared rewrites, in log order. `op` and `declared_in` are closed vocabularies and
    // `path` is schema-checked; `value` is customer or Gray content, and stays a JSON value here
    // (never a printed line, so no transcript escaping is needed).
    request_modified: (receipt?.modified ?? []).map((event) => ({
      op: event.op,
      path: event.path,
      ...(event.value === undefined ? {} : { value: event.value }),
      ...(event.value_sha256 === undefined ? {} : { value_sha256: event.value_sha256 }),
      declared_in: event.declared_in,
    })),
    // A relay-stack receipt's attempts (S26). Ids are schema-checked printable ASCII, and still
    // token-only here for the same reason as template ids.
    stack: receipt?.stack === null || receipt?.stack === undefined ? null : stackMachine(receipt.stack),
    attestation: {
      ok: input.attestedOk,
      nonce: input.attested.nonce,
      pinned: verification.pinned,
      compose_pinned: verification.composePinned,
      os_pinned: verification.osPinned,
      compose_hash: verification.composeHash,
      os_image_hash: verification.osImageHash,
      keyset_digest: input.attested.sealed?.digest ?? null,
      relay: relayMachine(verification.stackBoot),
    },
    checks: checks.map(checkValue),
  };
}

function stackMachine(stack: StackReceiptSummary): JsonObject {
  const nullableToken = (text: string | null): string | null => (text === null ? null : safeToken(text));
  return {
    attempts: stack.attempts.map((attempt) => ({
      n: safeToken(attempt.n),
      outcome: attempt.outcome,
      refused_code: nullableToken(attempt.refused_code),
      refused_header: nullableToken(attempt.refused_header),
      status: nullableToken(attempt.status),
      end_reason: nullableToken(attempt.end_reason),
      upstream_events_sha256: nullableToken(attempt.upstream_events_sha256),
      upstream_body_sha256: nullableToken(attempt.upstream_body_sha256),
      forwarded_body_sha256: nullableToken(attempt.forwarded_body_hash),
      forwarded_body_jcs_sha256: nullableToken(attempt.forwarded_body_jcs_sha256),
      request_modified: attempt.modified.map((event) => ({
        op: event.op,
        path: event.path,
        ...(event.value === undefined ? {} : { value: event.value }),
        ...(event.value_sha256 === undefined ? {} : { value_sha256: event.value_sha256 }),
        declared_in: event.declared_in,
      })),
      appended: attempt.appended.map((append) => ({
        template_id: safeToken(append.template_id),
        position: append.position,
        text_sha256: append.text_sha256,
      })),
      // The relay's own changes (docs/relay-request-changes.md), null when it changed nothing. Paths and
      // values are the relay's content and stay JSON strings (never a printed line); names are schema-checked tokens.
      relay_changes: attempt.changed === null ? null : relayChangesMachine(attempt.changed),
      tls_hello: attempt.tls_hello,
    })),
    status: nullableToken(stack.status),
    events_sha256: nullableToken(stack.events_sha256),
    body_sha256: nullableToken(stack.body_sha256),
    dropped: stack.dropped.map((entry) => ({ seq: safeToken(entry.seq), kind: safeToken(entry.kind) })),
    replaced_error: stack.replaced_error,
    served_attempt: nullableToken(stack.served_attempt),
    served_as: nullableToken(stack.served_as),
    // Gray's declared changes to the served answer (gray-lane-response-rewrites-v1): ops and paths of its closed list.
    rewrites: stack.rewrites.map((rewrite) => ({ seq: nullableToken(rewrite.seq), op: safeToken(rewrite.op), path: rewrite.path })),
    feed_incomplete: nullableToken(stack.feed_incomplete),
  };
}

function relayChangesMachine(changed: RelayStackChanges): JsonObject {
  const counts = (entry: { readonly removed_bytes: bigint; readonly added_bytes: bigint }) => ({ removed_bytes: entry.removed_bytes, added_bytes: entry.added_bytes });
  return {
    body: changed.body.map((entry) => ({ op: entry.op, path: entry.path, ...counts(entry), ...(entry.value_jcs === undefined ? {} : { value_jcs: entry.value_jcs }) })),
    headers: changed.headers.map((entry) => ({ op: entry.op, name: entry.name, ...counts(entry), ...(entry.value === undefined ? {} : { value: entry.value }) })),
    added_bytes: changed.added_bytes,
    removed_bytes: changed.removed_bytes,
    omitted: changed.omitted,
    values: changed.values,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Release lists from a file or a URL, and Gray's own entry
// ---------------------------------------------------------------------------------------------------------------

/**
 * A release list or freshness document: a file, or an https URL read with Node's own trust store (never `--ca`, which
 * is the entry's). Where a list came from decides nothing: it counts only under the release key (release-list.ts).
 * The bound is the signer's own (MAX_RELEASE_LIST_BYTES).
 */
async function readSource(source: string, what: string): Promise<string> {
  if (!/^https:\/\//i.test(source)) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source)) throw new UsageError(`${what} ${source}: give a file or an https URL`);
    return readText(source, what);
  }
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    throw new UsageError(`${what} ${source} is not a URL`);
  }
  if (url.username !== "" || url.password !== "") throw new UsageError(`${what} ${url.host}: the URL must not carry credentials`);
  const get = net.getPublic ?? (NODE_NET.getPublic as NonNullable<CliNet["getPublic"]>);
  let fetched: FetchedText;
  try {
    fetched = await get(url, MAX_RELEASE_LIST_BYTES);
  } catch (error) {
    throw new UsageError(`cannot fetch ${what} ${url.href}: ${messageOf(error)}`);
  }
  if (fetched.status !== 200) throw new UsageError(`cannot fetch ${what} ${url.href}: it answered ${String(fetched.status)}`);
  return fetched.text;
}

/** The pinning flags a command line names itself; any one of them turns the built-in lists off. */
const PIN_FLAG_NAMES: readonly string[] = ["allow", "allow-unpinned", "accept-unpinned", "release-key", "allow-freshness", "freshness-key"];

interface EntryDefaults {
  readonly args: ParsedArgs;
  /** The known entry whose list and keys were filled in, or null when none was. */
  readonly entry: KnownEntry | null;
  /** The transcript line that says so, or null. */
  readonly line: string | null;
}

/**
 * For Gray's own entry (`entries.ts`) and a command line that names no list or key: the list Gray publishes for it
 * (`entry`: the entry's own releases; `stack`: a provider's VM), its freshness document, and the built-in keys, as if
 * given as `--allow`, `--release-key`, `--allow-freshness` and `--freshness-key`.
 */
function entryDefaults(args: ParsedArgs, origin: URL, list: "entry" | "stack"): EntryDefaults {
  const entry = knownEntry(origin);
  if (entry === null || PIN_FLAG_NAMES.some((name) => args.flags.has(name))) return { args, entry: null, line: null };
  const url = list === "entry" ? entry.releaseList : entry.stackList;
  const flags = new Map(args.flags);
  const spelled = new Map(args.spelled);
  const filled: readonly (readonly [string, string])[] = [
    ["allow", url],
    ["release-key", entry.releaseKey],
    ["allow-freshness", releaseFreshnessLocation(url)],
    ["freshness-key", entry.freshnessKey],
  ];
  for (const [name, value] of filled) {
    flags.set(name, value);
    spelled.set(name, name);
  }
  return {
    args: { ...args, flags, spelled },
    entry,
    line: `release_list_source ${url}, release key ${entry.releaseKey}, freshness key ${entry.freshnessKey} (built in for ${entry.origin})`,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// check: one answer, every step
// ---------------------------------------------------------------------------------------------------------------

/** A receipt id as the entry names it in `x-receipt-id` (`rcpt_` and 32 lower-case hex digits). */
const RECEIPT_ID_FORM = /^rcpt_[0-9a-f]{32}$/;
const DEFAULT_WAIT_S = 30;
const MAX_WAIT_S = 600;
/** The longest single wait a `Retry-After` may ask for; the entry asks 1 s (receipts.ts RECEIPT_PENDING_RETRY_AFTER_S). */
const MAX_RETRY_AFTER_S = 10;

/** The key that made the request, from the environment only (a command line is visible to other processes); null when unset. */
function apiKeyFromEnvironment(): string | null {
  const apiKey = process.env.GRAY_API_KEY;
  if (apiKey === undefined || apiKey === "") return null;
  if (!/^[\x21-\x7e]{1,4096}$/.test(apiKey)) throw new UsageError("GRAY_API_KEY is not an API key (printable ASCII without spaces)");
  return apiKey;
}

function parseWait(text: string): number {
  if (!/^[0-9]{1,4}$/.test(text) || Number(text) > MAX_WAIT_S) throw new UsageError(`--wait is whole seconds, 0 to ${MAX_WAIT_S}`);
  return Number(text);
}

/** A `Retry-After` in whole seconds, 1 to MAX_RETRY_AFTER_S; anything else (absent, a date) is 1. */
function retryAfterSeconds(value: string | undefined): number {
  if (value === undefined || !/^[0-9]{1,6}$/.test(value.trim())) return 1;
  return Math.min(Math.max(Number(value.trim()), 1), MAX_RETRY_AFTER_S);
}

/** The `{error: {code}}` of an ACI error body as a printable token, or null. */
function errorCodeText(text: string): string | null {
  try {
    const code = get(get(parseStrict(text), "error"), "code");
    return typeof code === "string" ? safeToken(code) : null;
  } catch {
    return null;
  }
}

type ReceiptFetch =
  | {
    readonly ok: true;
    readonly text: string;
    /** The origin asked. */
    readonly asked: URL;
    /** The replica the receipt is held by: `--lane-origin`, or the one the answer's `x-gray-lane-origin` named; else null. */
    readonly laneOrigin: URL | null;
    /** Whether `laneOrigin` came from the answer's header rather than the flag. */
    readonly named: boolean;
    readonly pending: number;
    /** 1.8.0: the `503 receipt_lookup_unavailable` answers waited out. */
    readonly unavailable: number;
    readonly waitedS: number;
  }
  | { readonly ok: false; readonly asked: URL; readonly status: number; readonly detail: string; readonly pending: number; readonly unavailable: number; readonly waitedS: number };

/**
 * `GET <origin>/v1/aci/receipts/<id>` with the key that made the request (docs/trust-model.en.md, "Checking it"): at
 * `--lane-origin` when given, else at `--origin`; a `503 receipt_pending`, or (1.8.0) a `503 receipt_lookup_unavailable`
 * when the entry's receipt store did not answer, is asked again after its `Retry-After` until `waitS` is spent. An entry replica names itself in every answer's `x-gray-lane-origin` (ER6): the receipt is
 * that replica's, so that origin, read by the rule of `lane-origin.ts`, is the one attested. The header only says
 * where; the receipt still verifies only under the keyset attested there.
 */
async function fetchReceipt(input: {
  readonly origin: URL;
  readonly laneOrigin: URL | null;
  readonly receiptId: string;
  readonly apiKey: string;
  readonly ca: string | undefined;
  readonly waitS: number;
}): Promise<ReceiptFetch> {
  const asked = input.laneOrigin ?? input.origin;
  const url = new URL(`/v1/aci/receipts/${encodeURIComponent(input.receiptId)}`, asked);
  const sleep = net.sleep ?? (NODE_NET.sleep as NonNullable<CliNet["sleep"]>);
  let pending = 0;
  let unavailable = 0;
  let waitedS = 0;
  for (;;) {
    let answer: FetchedText;
    try {
      answer = await net.getWithKey(url, input.apiKey, input.ca, MAX_RECEIPT_BYTES);
    } catch (error) {
      throw new UsageError(`cannot fetch ${asked.origin}${url.pathname}: ${messageOf(error)}`);
    }
    const code = answer.status === 200 ? null : errorCodeText(answer.text);
    if (answer.status === 503 && (code === "receipt_pending" || code === RECEIPT_LOOKUP_UNAVAILABLE)) {
      const retryS = retryAfterSeconds(answer.headers?.["retry-after"]);
      if (waitedS + retryS > input.waitS) {
        const detail = code === "receipt_pending"
          ? `the entry still answers 503 receipt_pending after ${String(waitedS)} s: the answer may still be streaming; ask again, or give --wait more seconds`
          : `the entry still answers 503 ${RECEIPT_LOOKUP_UNAVAILABLE} after ${String(waitedS)} s: its receipt store did not answer; ask again later, or give --wait more seconds`;
        return { ok: false, asked, status: 503, pending, unavailable, waitedS, detail };
      }
      if (code === "receipt_pending") pending += 1;
      else unavailable += 1;
      await sleep(retryS * 1000);
      waitedS += retryS;
      continue;
    }
    if (answer.status !== 200) return { ok: false, asked, status: answer.status, pending, unavailable, waitedS, detail: receiptRefusal(answer, code, asked, input.laneOrigin !== null) };
    const named = answer.headers?.[LANE_ORIGIN_HEADER];
    if (named === undefined) return { ok: true, text: answer.text, asked, laneOrigin: input.laneOrigin, named: false, pending, unavailable, waitedS };
    const read = readLaneOrigin(named, input.origin);
    if (!read.ok) {
      return { ok: false, asked, status: 200, pending, unavailable, waitedS, detail: `the answer names ${transcriptText(named)} in ${LANE_ORIGIN_HEADER}, which is refused: ${read.reason}` };
    }
    if (input.laneOrigin !== null && read.origin.origin !== input.laneOrigin.origin) {
      return { ok: false, asked, status: 200, pending, unavailable, waitedS, detail: `asked ${input.laneOrigin.origin}, but the answer names ${read.origin.origin} in ${LANE_ORIGIN_HEADER} as the origin that answered` };
    }
    return { ok: true, text: answer.text, asked, laneOrigin: read.origin, named: input.laneOrigin === null, pending, unavailable, waitedS };
  }
}

/** ` after 2 pending answer(s) (4 s)` and the like, or nothing when the receipt came at once. */
function fetchWaits(fetched: { readonly pending: number; readonly unavailable: number; readonly waitedS: number }): string {
  const parts = [
    ...(fetched.pending === 0 ? [] : [`${String(fetched.pending)} pending answer(s)`]),
    ...(fetched.unavailable === 0 ? [] : [`${String(fetched.unavailable)} receipt_lookup_unavailable answer(s)`]),
  ];
  return parts.length === 0 ? "" : ` after ${parts.join(" and ")} (${String(fetched.waitedS)} s)`;
}

/** Why the entry gave no receipt, with what to do about it; the key is never named. */
function receiptRefusal(answer: FetchedText, code: string | null, asked: URL, laneGiven: boolean): string {
  const said = `${asked.origin} answered ${String(answer.status)}${code === null ? "" : ` ${code}`}`;
  if (answer.status === 401) return `${said}: present the key that made the request as GRAY_API_KEY`;
  if (answer.status === 404 && code === "receipt_not_found") {
    const there = answer.headers?.[LANE_ORIGIN_HEADER];
    const where = laneGiven
      ? ""
      : ` Only the copy of the entry that answered holds a receipt: pass the answer's ${LANE_ORIGIN_HEADER} header as --lane-origin${there === undefined ? "" : ` (this answer came from ${transcriptText(there)})`}.`;
    return `${said}: no receipt with this id for this key. The entry keeps a receipt for the time its signed retention_seconds says after the answer ends `
      + `(30 days on an entry that stores its receipts; an hour on a receipt without retention_seconds), and only for the key that made the request.${where}`
      + " A receipt id carries no signed time, so a receipt the entry no longer gives is a failure here; to check one after that time, check a saved receipt with --receipt.";
  }
  return said;
}

async function checkCommand(given: ParsedArgs): Promise<number> {
  assertFlags(given, ["receipt", "boot-report", "request", "origin", "lane-origin", "response", "wait", "templates", "protocol", "allow", "release-key", "allow-freshness", "freshness-key", "allow-stack", "allow-stack-freshness", "accept-os-unpinned", "ca", "now", "pccs", "verifier-module"]);
  if (given.positional.length > 1) throw new UsageError("check takes one receipt id");
  const receiptId = given.positional[0] ?? null;
  const savedPath = given.flags.get("receipt") ?? null;
  if ((receiptId === null) === (savedPath === null)) throw new UsageError("check needs a receipt id (the answer's x-receipt-id) or --receipt <saved receipt.json>: one of the two");
  if (receiptId !== null && !RECEIPT_ID_FORM.test(receiptId)) throw new UsageError("a receipt id is rcpt_ and 32 lower-case hex digits, as the answer's x-receipt-id names it");
  const bootReportPath = given.flags.get("boot-report") ?? null;
  if (bootReportPath !== null && savedPath === null) throw new UsageError("--boot-report goes with --receipt: a saved receipt and the /attestation answer saved for it");
  const requestPath = requiredFlag(given, "request");
  const origin = normalizeOrigin(given.flags.get("origin") ?? DEFAULT_ORIGIN);
  const laneOriginGiven = readLaneOriginFlag(given, origin);
  const waitS = given.flags.has("wait") ? parseWait(given.flags.get("wait") as string) : DEFAULT_WAIT_S;
  const apiKey = apiKeyFromEnvironment();
  if (receiptId !== null && apiKey === null) throw new UsageError("check <receipt id> needs the key that made the request in the environment: GRAY_API_KEY");

  const defaults = entryDefaults(given, origin, "entry");
  const args = defaults.args;
  const pins = readPinFlags(args, "receipt");
  if (pins.allowPath === null || pins.releaseKey === null) {
    throw new UsageError(`check needs Gray's signed release list for ${origin.origin}: pass --allow <file or URL> --release-key <64 hex> (built in only for ${DEFAULT_ORIGIN})`);
  }
  const stackGiven = args.flags.get("allow-stack") ?? null;
  const stackFreshnessGiven = args.flags.get("allow-stack-freshness") ?? null;
  if (stackFreshnessGiven !== null && stackGiven === null) throw new UsageError("--allow-stack-freshness goes with --allow-stack");
  if (stackFreshnessGiven !== null && pins.freshnessKey === null) throw new UsageError("--allow-stack-freshness needs --freshness-key <64 hex>");
  const stack = stackGiven !== null
    ? { list: stackGiven, freshness: stackFreshnessGiven }
    : defaults.entry !== null
      ? { list: defaults.entry.stackList, freshness: null }
      : null;
  const ca = args.flags.has("ca") ? readText(args.flags.get("ca") as string, "CA certificate") : undefined;
  const nowSecs = args.flags.has("now") ? parseUnixSeconds(args.flags.get("now") as string) : nowSeconds();
  const receivedBody = readBytes(requestPath, "request body");
  const responseBytes = args.flags.has("response") ? readBytes(args.flags.get("response") as string, "response body") : undefined;
  const templates = args.flags.has("templates") ? loadTemplates(args.flags.get("templates") as string) : [];
  const protocol = args.flags.has("protocol") ? parseProtocol(args.flags.get("protocol") as string) : undefined;
  const savedText = savedPath === null ? null : readText(savedPath, "receipt");
  const releaseKeyHex = args.flags.get("release-key") as string;
  const pinned = await loadReleaseList(pins.allowPath, pins.releaseKey, nowSecs, { ...pins, freshnessOptional: defaults.entry !== null });
  const quoteVerifier = await loadQuoteVerifier(args, nowSecs);

  const title = `gray-lane-verify check ${receiptId ?? savedPath}\n`;
  const preamble = (): void => {
    out(title);
    out(`origin ${origin.origin}\n`);
    if (defaults.line !== null) out(`${defaults.line}\n`);
    out(`${pinned.line}\n`);
  };

  // 1. The receipt: fetched, or the saved one.
  let receiptText: string;
  let laneOrigin = laneOriginGiven;
  let fetched: Extract<ReceiptFetch, { ok: true }> | null = null;
  if (receiptId !== null) {
    const answer = await fetchReceipt({ origin, laneOrigin: laneOriginGiven, receiptId, apiKey: apiKey as string, ca, waitS });
    if (!answer.ok) {
      preamble();
      printChecks([{ id: "receipt_fetch", status: "fail", detail: answer.detail }]);
      out("VERDICT: FAIL\n");
      out(`${toJsonString({
        command: "check",
        ok: false,
        verdict: "FAIL",
        receipt_id: receiptId,
        origin: origin.origin,
        ...(laneOriginGiven === null ? {} : { lane_origin: laneOriginGiven.origin }),
        fetch: { from: answer.asked.origin, status: BigInt(answer.status), pending_answers: BigInt(answer.pending), unavailable_answers: BigInt(answer.unavailable), waited_s: BigInt(answer.waitedS) },
        checks: [{ id: "receipt_fetch", status: "fail", detail: transcriptText(answer.detail) }],
      })}\n`);
      return 1;
    }
    fetched = answer;
    receiptText = answer.text;
    laneOrigin = answer.laneOrigin;
  } else {
    receiptText = savedText as string;
  }

  // 2. Attest the origin the receipt came from, and verify the receipt under the keyset it shows. With --boot-report
  // no origin is attested: the receipt is verified under the boot report saved for it.
  const attestAt = laneOrigin ?? origin;
  const attested = bootReportPath === null ? await attestFromOrigin(attestAt, pinned.list, ca, nowSecs, quoteVerifier) : null;
  const sealed = attested?.sealed ?? null;
  const attestedOk = attested !== null && attestedOkFrom(attested, pins);
  const fetchLine = (fetched === null
    ? `receipt read from ${savedPath as string}\n`
    : `receipt fetched from ${fetched.asked.origin}${fetchWaits(fetched)}\n`)
    + (bootReportPath === null ? "" : `boot_report: ${transcriptText(bootReportPath)} (a saved /attestation answer): ${origin.origin} is not attested; the receipt is verified under that boot report and the release list alone\n`);
  const laneLine = laneOrigin === null
    ? ""
    : `lane_origin: ${laneOrigin.origin} (${fetched?.named === true ? `named by the answer's ${LANE_ORIGIN_HEADER}` : LANE_ORIGIN_HEADER}, a replica of ${origin.origin})\n`;
  const checkMachine = (base: JsonObject, ok: boolean, verdict: string, peers: PeerReceiptsVerification | null): JsonObject => ({
    ...base,
    command: "check",
    ok,
    verdict,
    origin: origin.origin,
    ...(laneOrigin === null ? {} : { lane_origin: laneOrigin.origin }),
    fetch: fetched === null ? null : { from: fetched.asked.origin, status: 200n, pending_answers: BigInt(fetched.pending), unavailable_answers: BigInt(fetched.unavailable), waited_s: BigInt(fetched.waitedS), lane_origin_named: fetched.named },
    release_key: releaseKeyHex,
    release_list: pinned.machine,
    peers: peers === null ? [] : peersMachine(peers),
  });
  if (attested !== null && (!attestedOk || sealed === null)) {
    preamble();
    out(fetchLine);
    out(laneLine);
    printChecks(attested.verification.checks);
    printChecks([{ id: "keyset_attestation", status: "fail", detail: attestationFailure(attested.verification, pins, sealed?.digest ?? null) }]);
    out("VERDICT: FAIL\n");
    out(`${toJsonString(checkMachine(receiptMachine({ attested, attestedOk, pins, receipt: null }), false, "FAIL", null))}\n`);
    return 1;
  }
  // 1.8.0: a receipt of an earlier boot is verified under the keyset of the boot report the entry stored for it.
  const stored = await storedFor({
    receiptText,
    live: attested,
    bootReportPath,
    origin: attestAt,
    apiKey,
    ca,
    waitS: Math.max(waitS - (fetched?.waitedS ?? 0), 0),
    list: pinned.list,
    pins,
    args,
    nowSecs,
  });
  if (stored !== null && !stored.ok) {
    preamble();
    out(fetchLine);
    out(laneLine);
    printChecks(stored.checks);
    out("VERDICT: FAIL\n");
    const base = checkMachine(attested === null ? { receipt_id: null, keyset_digest: null } : receiptMachine({ attested, attestedOk, pins, receipt: null }), false, "FAIL", null);
    out(`${toJsonString({ ...base, checks: stored.checks.map(checkValue), ...(stored.machine === null ? {} : { stored_attestation: stored.machine }) })}\n`);
    return 1;
  }
  const used = stored === null ? (attested as AttestedKeyset) : stored.attested;
  const keyset = used.sealed as SealedKeyset;
  const relayImage = attestedRelayImage(used.verification.stackBoot);
  const receipt = await verifyResponseReceiptText(receiptText, {
    receivedBody,
    templates,
    keyset,
    expectedKeysetDigest: keyset.digest,
    ...(relayImage === undefined ? {} : { expectedRelayImage: relayImage }),
    ...(responseBytes === undefined ? {} : { responseBytes }),
    ...(protocol === undefined ? {} : { protocol }),
  });

  // The entry answered for the id asked: the receipt must be that one, not another receipt of the same key.
  const idCheck: VerifyCheck[] = receiptId === null
    ? []
    : [receipt.receiptId === receiptId
      ? { id: "receipt_id", status: "pass", detail: `${receiptId}, the id asked for` }
      : { id: "receipt_id", status: "fail", detail: `asked for ${receiptId}, the entry answered the receipt ${receipt.receiptId === null ? "(none)" : safeToken(receipt.receiptId)}` }];

  // 3. The provider's VM: every attempt the receipt names there, from the records the same origin serves.
  const outer = parseReceiptText(receiptText);
  const peerCount = outer.ok ? peerNumbersToFetch(outer.value).length : 0;
  let peers: PeerReceiptsVerification | null = null;
  if (peerCount > 0) {
    if (apiKey === null) {
      peers = { ok: false, peers: [], expired: [], tied: null, checks: [{ id: "peers", status: "fail", detail: `the receipt names ${String(peerCount)} attempt(s) in a provider's VM, whose records are read with the key that made the request: set GRAY_API_KEY` }] };
    } else if (stack === null) {
      peers = { ok: false, peers: [], expired: [], tied: null, checks: [{ id: "peers", status: "fail", detail: `the receipt names ${String(peerCount)} attempt(s) in a provider's VM: pass --allow-stack <Gray's signed stack release list> to check them` }] };
    } else {
      const freshnessFrom = stackFreshnessSource(stack.list, stack.freshness, pins.freshnessKey);
      const freshnessText = freshnessFrom === null
        ? null
        : freshnessFrom.optional
          ? await readSource(freshnessFrom.source, "stack freshness document").catch(() => null)
          : await readSource(freshnessFrom.source, "stack freshness document");
      const list: PeerReleaseList = {
        text: await readSource(stack.list, "stack release list"),
        publicKey: pins.releaseKey,
        ...(freshnessFrom === null || pins.freshnessKey === null ? {} : { freshness: { text: freshnessText, publicKey: pins.freshnessKey } }),
      };
      peers = await peerChecks({
        // What the receipt's own fetch and its stored report's left of --wait.
        flags: { apiKey, list, waitS: Math.max(waitS - (fetched?.waitedS ?? 0) - (stored?.waitedS ?? 0), 0) },
        origin: attestAt,
        receiptText,
        receipt,
        receivedBody,
        ...(responseBytes === undefined ? {} : { responseBytes }),
        templates,
        ca,
        nowSecs,
        quoteVerifier,
      });
    }
  }

  const ok = receipt.ok && idCheck.every((entry) => entry.status !== "fail") && (peers === null || peers.ok);
  const outcome = receiptOutcome(receipt, idCheck.every((entry) => entry.status !== "fail") && !peersFailed(peers), peersExpired(peers), used.verification.osPinned);
  const verdict = outcome.verdict;
  const note = stored === null ? "" : STORED_NOTE;
  preamble();
  out(fetchLine);
  out(laneLine);
  printChecks([{
    id: "keyset_attestation",
    status: "pass",
    detail: `${keyset.digest}; compose ${used.verification.composeHash ?? "(unpinned)"}${used.verification.osPinned ? "" : " (OS unpinned, accepted)"}${note}`,
  }]);
  if (stored !== null) {
    printChecks(stored.checks);
    for (const line of stored.lines) out(line);
  }
  const shown = joinedReceipt(receipt, peers);
  printChecks(idCheck);
  printChecks(shown.checks);
  if (peers !== null) printChecks(peers.checks);
  if (outcome.valid) {
    printCheckSummary({
      receiptId: receipt.receiptId,
      fetched,
      savedPath,
      attestAt,
      digest: keyset.digest,
      verification: used.verification,
      storedAttestedAt: stored === null ? null : stored.attestedAt,
      bootReportPath,
      releaseKeyHex,
      receipt: shown,
      peers,
      responseGiven: responseBytes !== undefined,
    });
  }
  out(`VERDICT: ${verdict}\n`);
  const machine = checkMachine(receiptMachine({ attested: used, attestedOk: true, pins, receipt: shown, note, extra: stored?.checks ?? [] }), ok, verdict, peers);
  out(`${toJsonString({ ...machine, ...(stored === null ? {} : { stored_attestation: stored.machine }), ...expiredMachine(peers), ...partialMachine(receipt), checks: [...idCheck.map(checkValue), ...(machine.checks as Json[])] })}\n`);
  return ok ? 0 : outcome.code;
}

/** What a passing `check` covered, in plain lines (facts from the checks above, never a verdict of their own). */
function printCheckSummary(input: {
  readonly receiptId: string | null;
  readonly fetched: Extract<ReceiptFetch, { ok: true }> | null;
  readonly savedPath: string | null;
  readonly attestAt: URL;
  readonly digest: string;
  readonly verification: AttestationVerification;
  /** 1.8.0: when the keyset came from an earlier boot's stored report, that boot's `attested_at`; else null. */
  readonly storedAttestedAt: bigint | null;
  /** 1.8.0: the saved `/attestation` answer (`--boot-report`) the stored report was read from; null when fetched. */
  readonly bootReportPath: string | null;
  readonly releaseKeyHex: string;
  readonly receipt: Awaited<ReturnType<typeof verifyResponseReceiptText>>;
  readonly peers: PeerReceiptsVerification | null;
  readonly responseGiven: boolean;
}): void {
  const id = input.receiptId === null ? "(no id)" : safeToken(input.receiptId);
  const where = input.fetched === null
    ? `read from ${input.savedPath as string}`
    : `fetched from ${input.fetched.asked.origin}${input.fetched.named ? `, which named ${input.attestAt.origin} as the copy that holds it` : ""}`;
  const verification = input.verification;
  out("covered:\n");
  out(`  receipt    ${id}, ${where}\n`);
  out(input.storedAttestedAt === null
    ? `  signature  signed with a key of keyset ${input.digest}, which remote attestation of ${input.attestAt.origin} shows\n`
    : `  signature  signed with a key of keyset ${input.digest}, which the boot report ${input.bootReportPath === null ? `${input.attestAt.origin} stored for an earlier boot` : `saved in ${transcriptText(input.bootReportPath)}`} shows (attested at boot, ${String(input.storedAttestedAt)}; that boot need not run now)\n`);
  out(`  release    that confidential VM runs compose ${verification.composeHash ?? "(none)"}, listed in Gray's release list signed by ${input.releaseKeyHex}`
    + `${verification.osPinned ? `; OS image ${verification.osImageHash ?? "(none)"} pinned` : "; OS image not pinned (accepted with --accept-os-unpinned)"}\n`);
  const rewrites: string[] = [];
  const requestOps = (input.receipt.modified.length) + (input.receipt.stack?.attempts.reduce((sum, attempt) => sum + attempt.modified.length, 0) ?? 0);
  for (const rewrite of input.receipt.stack?.rewrites ?? []) rewrites.push(rewrite.path);
  const served = input.peers?.peers ?? [];
  if (served.length === 0) {
    out("  provider   the receipt names no attempt in a provider's VM\n");
  }
  let peerOps = 0;
  for (const peer of served) {
    out(`  provider   attempt ${safeToken(peer.n)}: deployment ${peer.relay_id === null ? "(unnamed)" : safeToken(peer.relay_id)}, image ${peer.relay_image === null ? "(none)" : transcriptText(peer.relay_image)}; `
      + `its VM's attestation (compose ${peer.compose_hash === null ? "(none)" : safeToken(peer.compose_hash)}) and its own receipt ${peer.inner_receipt_id === null ? "(none)" : safeToken(peer.inner_receipt_id)} checked\n`);
    for (const attempt of peer.stack?.attempts ?? []) peerOps += attempt.modified.length;
    for (const rewrite of peer.stack?.rewrites ?? []) rewrites.push(rewrite.path);
  }
  const counted = new Map<string, number>();
  for (const path of rewrites) counted.set(path, (counted.get(path) ?? 0) + 1);
  const rewritten = [...counted].map(([path, count]) => (count === 1 ? transcriptText(path) : `${transcriptText(path)} (${String(count)} events)`)).join(", ");
  out(`  changes    Gray declared ${String(requestOps + peerOps)} change(s) to the request; answer rewrites: ${rewritten === "" ? "none" : rewritten}\n`);
  const formOps = input.receipt.modified.filter((op) => op.op === "set_form_field" || op.op === "remove_form_field");
  if (formOps.length > 0) {
    out(`  form       Gray changed the field(s) ${formOps.map((op) => transcriptText(op.path)).join(", ")} of your multipart form and no other byte, files included; `
      + "replayed on the form as the boundary of its first line reads it. The receipt does not carry the content-type Gray sent the provider\n");
  }
  const translation = input.receipt.translation;
  if (translation !== null) {
    const cap = translation.output_cap === null ? "" : `, output cap ${translation.output_cap.toString()} written by Gray`;
    out(`  translated your request, by Gray from ${translation.from} to ${translation.to}${cap}, dropped: ${translation.dropped.length === 0 ? "none" : translation.dropped.join(", ")}; `
      + "the forwarded body is exactly that translation of your bytes with Gray's declared ops, replayed here with the same open-source code\n");
    out(`  translated the answer, back to ${translation.from}: not replayed; the receipt hashes the answer as you received it, and a receipt of a provider's API carries no digest of the provider's answer\n`);
  }
  out(`  answer     ${input.responseGiven ? "the bytes you received match what the receipt records" : "not compared: pass --response <the raw bytes you received> to compare them"}\n`);
  if (input.receipt.arrival === RECEIPT_ARRIVAL_GRAY_API) {
    out("  client     not covered: the request arrived through Gray's API, where your TLS connection ended at Cloudflare; send it to the entry itself for a connection that ends in the VM\n");
  }
}

function loadTemplates(path: string): TemplateText[] {
  const value = parseJsonText(readText(path, "template texts"), "the template texts");
  let entries: Json | undefined = value;
  if (isObject(value) && value.templates !== undefined) entries = value.templates;
  const templates: TemplateText[] = [];
  if (Array.isArray(entries)) {
    for (const entry of entries) {
      if (!isObject(entry) || typeof entry.template_id !== "string" || typeof entry.text !== "string") {
        throw new UsageError("each template needs a string template_id and a string text");
      }
      templates.push({ template_id: entry.template_id, text: entry.text });
    }
    return templates;
  }
  if (isObject(entries)) {
    for (const key of Object.keys(entries)) {
      const text = entries[key];
      if (typeof text !== "string") throw new UsageError(`template ${key} is not a string`);
      templates.push({ template_id: key, text });
    }
    return templates;
  }
  throw new UsageError("templates must be an array, a {template_id: text} object, or {templates: ...}");
}

function parseProtocol(value: string): ReceiptProtocol {
  if (value !== "gemini" && !isRewriteApi(value)) throw new UsageError(`unknown protocol ${JSON.stringify(value)}`);
  return value;
}

function requiredFlag(args: ParsedArgs, name: string): string {
  const value = args.flags.get(name);
  if (value === undefined) throw new UsageError(`missing --${name}`);
  return value;
}

function readBytes(path: string, what: string): Uint8Array {
  try {
    return new Uint8Array(readFileSync(path));
  } catch (error) {
    throw new UsageError(`cannot read ${what} ${path}: ${messageOf(error)}`);
  }
}

// Only as a script: a test imports `main` and calls it in-process (D60). The `bin` is a symlink and
// the spawn cases go through one, so argv[1] names the link while the ESM loader reports the real
// path in `import.meta.url`; compare real paths (D81). An argv[1] that cannot be resolved
// makes the guard false, so an import can never start a run.
function invokedAsScript(): boolean {
  if (process.argv[1] === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (invokedAsScript()) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
