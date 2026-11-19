/**
 * `attest --via <entry> --relay <relay id>` (docs/design/relay-outbound-only.md §5 "Customers", §6): the attestation of
 * a relay-stack VM that takes no inbound connection, fetched through Gray's entry.
 *
 * The wire form is gray-assistant's (relay-kit `src/node/peer-tunnel.ts`, #376), which this package cannot import (relay-kit
 * depends on it):
 *
 * 1. **Outer:** a WebSocket to `wss://<entry>/v1/peer/tunnel/<relay>` (`ws`), checked with WebPKI for the entry's name
 *    (`--ca` replaces Node's roots, as for `attest <origin>`). That only gets the bytes to Cloudflare and the entry;
 *    nothing the CLI checks depends on it.
 * 2. **Inner:** TLS inside the WebSocket (`createWebSocketStream` under `tls.connect({ socket })`), ending in the VM's
 *    workerd. The VM's certificate is self-signed per boot (§3.9), so there is no WebPKI step for it: the CLI records
 *    the leaf's SPKI, and `verifyAttestation` requires the attested keyset to bind it, exactly as for `attest <origin>`.
 * 3. **Request:** one `GET /v1/aci/attestation?nonce=…` over HTTP/1.1, `Connection: close`. Nothing else is sent: the
 *    CLI sends no body, so attest mode (no pin yet) is all it ever needs.
 *
 * The entry forwards ciphertext. It can delay or drop the exchange; it cannot read or forge the report, whose nonce
 * and TLS key the quote binds.
 */
import { createHash, X509Certificate } from "node:crypto";
import { request as httpRequest, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { connect as tlsConnect, type PeerCertificate, type TLSSocket } from "node:tls";
import { parsePlain } from "@gray/json";
import WebSocket, { createWebSocketStream } from "ws";

/** The entry's tunnel route (§5); gray-assistant's `PEER_TUNNEL_PATH`. */
export const PEER_TUNNEL_PATH = "/v1/peer/tunnel/";
/** The largest WebSocket message read from the entry; the entry sends at most 64 KiB (§3.4). */
const MAX_TUNNEL_MESSAGE_BYTES = 1024 * 1024;
/** How much of a refusal's body is read for its code. */
const MAX_REFUSAL_BYTES = 4 * 1024;
/** How long a closing tunnel waits for the entry's close frame before the socket is dropped. */
const CLOSE_GRACE_MS = 2_000;

/** The entry refused the tunnel: its status, its code (`peer_relay_unknown`, …) and what that means, in English. */
export class TunnelRefusedError extends Error {
  override readonly name = "TunnelRefusedError";
  // Plain fields, not parameter properties: Node runs this file with strip-only type stripping (the bin).
  readonly status: number;
  readonly code: string | null;
  constructor(status: number, code: string | null, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface TunnelFetchInput {
  /** The entry's origin, `https://<entry>[:port]`. */
  readonly entry: URL;
  /** The relay whose VM the tunnel reaches. */
  readonly relayId: string;
  /** The inner request's path and query, as the VM's lane sees it. */
  readonly path: string;
  /** A trust store for the entry's certificate (the outer TLS); replaces Node's roots, as `--ca` does. */
  readonly ca?: string;
  readonly userAgent: string;
  readonly timeoutMs: number;
  readonly maxBytes: number;
}

export interface TunnelFetched {
  readonly status: number;
  readonly text: string;
  /** SHA-256 of the DER SPKI of the certificate the VM presented inside the tunnel. */
  readonly spkiSha256: string;
}

/**
 * `https://<entry>/v1/peer/tunnel/<relay>`: the origin gray-assistant names the VM by (§5), written as relay-kit's
 * `tunnelOriginFromUrl` writes it (the relay id as it is); the WebSocket URL encodes it (`openTunnel`).
 */
export function tunnelOrigin(entry: URL, relayId: string): string {
  return `${entry.origin}${PEER_TUNNEL_PATH}${relayId}`;
}

/** One GET to the VM through the entry's tunnel, TLS end to end, recording the SPKI the VM presented. */
export async function fetchThroughTunnel(input: TunnelFetchInput): Promise<TunnelFetched> {
  const deadline = Date.now() + input.timeoutMs;
  const remaining = (): number => Math.max(1, deadline - Date.now());
  const ws = await openTunnel(input, remaining());
  const stream = createWebSocketStream(ws);
  let socket: TLSSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await new Promise<TunnelFetched>((resolve, reject) => {
      let settled = false;
      const fail = (error: Error): void => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      timer = setTimeout(() => fail(new Error("the request through the entry timed out")), remaining());
      stream.on("error", () => fail(new Error("the tunnel through the entry closed")));
      // No WebPKI for the VM: its certificate is self-signed per boot, and the attestation's keyset is the check.
      const tls = tlsConnect({ socket: stream as Duplex, rejectUnauthorized: false });
      socket = tls;
      tls.once("error", (error) => fail(new Error(`the TLS connection to the VM through the entry failed: ${error.message}`)));
      tls.once("secureConnect", () => {
        let spkiSha256: string;
        try {
          const certificate = tls.getPeerCertificate(false);
          if (certificate === null || certificate === undefined || certificate.raw === undefined) throw new Error("no certificate");
          spkiSha256 = spkiOf(certificate);
        } catch {
          fail(new Error("the VM presented no TLS certificate inside the tunnel"));
          return;
        }
        const request = httpRequest(
          {
            createConnection: () => tls,
            method: "GET",
            path: input.path,
            headers: { accept: "application/json", "user-agent": input.userAgent, host: input.entry.host, connection: "close" },
          },
          (response: IncomingMessage) => {
            const chunks: Buffer[] = [];
            let size = 0;
            response.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > input.maxBytes) {
                response.destroy();
                fail(new Error(`the answer is larger than ${input.maxBytes} bytes`));
                return;
              }
              chunks.push(chunk);
            });
            response.on("error", (error) => fail(error));
            response.on("end", () => {
              if (settled) return;
              settled = true;
              resolve({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8"), spkiSha256 });
            });
          },
        );
        request.on("error", (error) => fail(error));
        request.end();
      });
    });
  } finally {
    if (timer !== null) clearTimeout(timer);
    (socket as TLSSocket | null)?.destroy();
    closeTunnel(ws);
  }
}

/**
 * Open the entry's tunnel route. Throws an Error when the entry cannot be reached (DNS, TCP, its TLS certificate), and a
 * `TunnelRefusedError` when it answers with anything but the upgrade (no such relay, no VM session, too many tunnels).
 */
function openTunnel(input: TunnelFetchInput, timeoutMs: number): Promise<WebSocket> {
  const url = `wss://${input.entry.host}${PEER_TUNNEL_PATH}${encodeURIComponent(input.relayId)}`;
  return new Promise<WebSocket>((resolve, reject) => {
    let settled = false;
    const ws = new WebSocket(url, {
      ...(input.ca === undefined ? {} : { ca: input.ca }),
      handshakeTimeout: timeoutMs,
      perMessageDeflate: false,
      followRedirects: false,
      maxPayload: MAX_TUNNEL_MESSAGE_BYTES,
      headers: { "user-agent": input.userAgent },
    });
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      ws.terminate();
      reject(error);
    };
    ws.once("unexpected-response", (request, response) => {
      void readRefusal(response).then((code) => {
        request.destroy();
        const status = response.statusCode ?? 0;
        fail(new TunnelRefusedError(status, code, refusalMessage(input.entry.host, input.relayId, status, code)));
      });
    });
    ws.once("error", (error: Error & { readonly code?: unknown }) => {
      const code = typeof error.code === "string" ? ` (${error.code})` : "";
      fail(new Error(`the entry ${input.entry.host} is unreachable${code}: ${error.message}`));
    });
    ws.once("open", () => {
      if (settled) return;
      settled = true;
      resolve(ws);
    });
  });
}

/** Close a tunnel with a normal close frame, and drop it if the entry does not answer in time. */
function closeTunnel(ws: WebSocket): void {
  if (ws.readyState === WebSocket.CLOSED) return;
  const drop = setTimeout(() => ws.terminate(), CLOSE_GRACE_MS);
  drop.unref();
  ws.once("close", () => clearTimeout(drop));
  try {
    ws.close(1000);
  } catch {
    ws.terminate();
  }
}

/** The refusal's code: the lane's `{"error":"<code>"}` or `{"error":{"code":"<code>"}}`; null when there is none. */
function readRefusal(response: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const finish = (): void => {
      if (done) return;
      done = true;
      let code: string | null = null;
      try {
        const value = parsePlain(Buffer.concat(chunks).toString("utf8")) as { readonly error?: unknown; readonly code?: unknown };
        const error = value.error;
        if (typeof error === "string") code = error;
        else if (typeof error === "object" && error !== null && typeof (error as { code?: unknown }).code === "string") code = (error as { code: string }).code;
        else if (typeof value.code === "string") code = value.code;
      } catch {
        code = null;
      }
      resolve(code !== null && /^[a-z0-9_]{1,64}$/u.test(code) ? code : null);
    };
    response.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_REFUSAL_BYTES) chunks.push(chunk);
      else response.destroy();
    });
    response.once("end", finish);
    response.once("close", finish);
    response.once("error", finish);
  });
}

/** What a refusal means to a customer verifying a relay's VM (§3.5, §5), in English. */
export function refusalMessage(entryHost: string, relayId: string, status: number, code: string | null): string {
  const named = code === null ? `${status}` : `${status} ${code}`;
  const why =
    code === "peer_link_unavailable"
      ? "the entry's link service is not answering (the entry is restarting or overloaded); try again"
      : code === "peer_relay_unknown" || (code === null && status === 404)
        ? `the entry knows no deployment ${relayId}; check the deployment id`
        : code === "peer_session_missing" || (code === null && status === 503)
          ? "the deployment's VM has no session to the entry right now (it is booting, rebooting or cannot reach Gray); try again"
          : code === "peer_tunnel_busy" || status === 429
            ? `too many tunnels to ${relayId} are open at once; try again`
            : "the entry did not open the tunnel";
  return `the entry ${entryHost} refused the tunnel to ${relayId} (${named}): ${why}`;
}

/** SHA-256 of the DER SubjectPublicKeyInfo, as ACI's `tls_public_keys` names it (`cli.ts` `spkiOf`). */
function spkiOf(certificate: PeerCertificate): string {
  const key = new X509Certificate(certificate.raw).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(key).digest("hex");
}
