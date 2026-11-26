/**
 * The boot report an entry stored for the receipts its boot signed (docs/design/persisted-receipts.md section 6):
 *
 *     GET /v1/aci/receipts/{id}/attestation
 *       → {receipt_id, keyset_digest, report, nonce, attested_at, collateral | null, collateral_check | null}
 *
 * `nonce` is `hex(SHA-256(utf8("gray-lane-boot-report/v1") || utf8(keyset_digest)))` (`bootReportNonce`): no verifier
 * chose it, so the report proves that the keyset came from the measured TD, not that the TD runs now. `collateral` is
 * the Intel-signed collateral the boot verified its own quote with (dcap-qvl's `Collateral`, byte members as hex, the
 * PCK chain included) and `collateral_check` when and with what result. The reader checks the members' forms only;
 * gray-lane-verify's `receipt` and `check` verify the report (node/cli.ts). Unknown members are ignored.
 */
import { sha256BareHex, utf8Bytes } from "@gray/attest";
import { get, isObject, parseStrict, type Json } from "@gray/json";

/** The label the boot report's nonce is derived under. */
export const BOOT_REPORT_NONCE_DOMAIN = "gray-lane-boot-report/v1";

/** The nonce an entry boot attests its keyset with, for a verifier that reads the report later. */
export function bootReportNonce(keysetDigest: string): string {
  return sha256BareHex(utf8Bytes(`${BOOT_REPORT_NONCE_DOMAIN}${keysetDigest}`));
}

/** dcap-qvl's `Collateral` as the entry stored it: every member text, the byte members lower-case hex. */
export interface StoredCollateral {
  readonly pck_crl_issuer_chain: string;
  readonly root_ca_crl: string;
  readonly pck_crl: string;
  readonly tcb_info_issuer_chain: string;
  readonly tcb_info: string;
  readonly tcb_info_signature: string;
  readonly qe_identity_issuer_chain: string;
  readonly qe_identity: string;
  readonly qe_identity_signature: string;
  /** The quote's own PCK chain, which dcap-qvl reads first. */
  readonly pck_certificate_chain?: string;
}

export interface StoredCollateralCheck {
  /** Unix seconds: when the boot verified its quote with the collateral, the clock it is verified at again. */
  readonly checked_at: bigint;
  readonly tcb_status: string;
  readonly advisory_ids: readonly string[];
}

export interface StoredAttestation {
  readonly receipt_id: string;
  readonly keyset_digest: string;
  readonly report: Json;
  readonly nonce: string;
  readonly attested_at: bigint;
  readonly collateral: StoredCollateral | null;
  readonly collateral_check: StoredCollateralCheck | null;
}

export type ReadStoredAttestationResult = { readonly ok: true; readonly answer: StoredAttestation } | { readonly ok: false; readonly message: string };

const COLLATERAL_TEXTS = [
  "pck_crl_issuer_chain",
  "root_ca_crl",
  "pck_crl",
  "tcb_info_issuer_chain",
  "tcb_info",
  "tcb_info_signature",
  "qe_identity_issuer_chain",
  "qe_identity",
  "qe_identity_signature",
] as const;
const HEX32 = /^[0-9a-f]{64}$/;
const KEYSET_DIGEST = /^sha256:[0-9a-f]{64}$/;
const RECEIPT_ID = /^rcpt_[0-9a-f]{32}$/;
const MAX_U64 = (1n << 64n) - 1n;

/** Read the answer's text with the strict reader (duplicate keys refused, integers as bigint). */
export function readStoredAttestationText(text: string): ReadStoredAttestationResult {
  let value: Json;
  try {
    value = parseStrict(text);
  } catch (error) {
    return { ok: false, message: `not JSON: ${error instanceof Error ? error.message : String(error)}` };
  }
  return readStoredAttestation(value);
}

/** The same check on a value already read with the strict reader. */
export function readStoredAttestation(value: Json): ReadStoredAttestationResult {
  const refuse = (message: string): ReadStoredAttestationResult => ({ ok: false, message });
  if (!isObject(value)) return refuse("the answer is not an object");
  const receiptId = get(value, "receipt_id");
  const keysetDigest = get(value, "keyset_digest");
  const report = get(value, "report");
  const nonce = get(value, "nonce");
  const attestedAt = get(value, "attested_at");
  if (typeof receiptId !== "string" || !RECEIPT_ID.test(receiptId)) return refuse("receipt_id is not rcpt_ and 32 hex");
  if (typeof keysetDigest !== "string" || !KEYSET_DIGEST.test(keysetDigest)) return refuse("keyset_digest is not sha256: and 64 hex");
  if (!isObject(report)) return refuse("report is not an object");
  if (typeof nonce !== "string" || !HEX32.test(nonce)) return refuse("nonce is not 32 bytes as lower-case hex");
  if (typeof attestedAt !== "bigint" || attestedAt < 0n || attestedAt > MAX_U64) return refuse("attested_at is not Unix seconds");
  const collateralValue = get(value, "collateral");
  const checkValue = get(value, "collateral_check");
  let collateral: StoredCollateral | null = null;
  if (collateralValue !== null) {
    if (!isObject(collateralValue)) return refuse("collateral is not an object or null");
    for (const member of COLLATERAL_TEXTS) {
      if (typeof get(collateralValue, member) !== "string") return refuse(`collateral.${member} is not text`);
    }
    const chain = get(collateralValue, "pck_certificate_chain");
    if (chain !== undefined && typeof chain !== "string") return refuse("collateral.pck_certificate_chain is not text");
    collateral = Object.fromEntries([...COLLATERAL_TEXTS, ...(chain === undefined ? [] : ["pck_certificate_chain"])].map((member) => [member, get(collateralValue, member) as string])) as unknown as StoredCollateral;
  }
  let check: StoredCollateralCheck | null = null;
  if (checkValue !== null) {
    if (!isObject(checkValue)) return refuse("collateral_check is not an object or null");
    const checkedAt = get(checkValue, "checked_at");
    const status = get(checkValue, "tcb_status");
    const advisories = get(checkValue, "advisory_ids");
    if (typeof checkedAt !== "bigint" || checkedAt < 0n || checkedAt > MAX_U64) return refuse("collateral_check.checked_at is not Unix seconds");
    if (typeof status !== "string" || status === "") return refuse("collateral_check.tcb_status is not text");
    if (!Array.isArray(advisories) || !advisories.every((id) => typeof id === "string")) return refuse("collateral_check.advisory_ids is not a list of texts");
    check = { checked_at: checkedAt, tcb_status: status, advisory_ids: advisories as string[] };
  }
  if (collateral !== null && check === null) return refuse("collateral without collateral_check: the time to verify it at is missing");
  return { ok: true, answer: { receipt_id: receiptId, keyset_digest: keysetDigest, report, nonce, attested_at: attestedAt, collateral, collateral_check: check } };
}

/** The `issueDate` of the collateral's TCB info, as Intel wrote it; null when it cannot be read. */
export function collateralIssueDate(collateral: Pick<StoredCollateral, "tcb_info">): string | null {
  try {
    const value = parseStrict(collateral.tcb_info);
    const date = get(get(value, "tcbInfo") ?? value, "issueDate");
    return typeof date === "string" && date.length <= 64 ? date : null;
  } catch {
    return null;
  }
}
