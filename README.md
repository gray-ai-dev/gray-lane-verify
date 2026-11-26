# gray-lane-verify 1.7.1 (v1.7.1-7f264111a618)

The source of `gray-lane-verify` 1.7.1, built from Gray's commit `7f264111a6185ce0f01cdea77ab0a4404a12d9bf`. gray-lane-verify checks one answer
from Gray's confidential entry in one command. It fetches the answer's signed receipt and checks the remote attestation
of the confidential VM that signed it against Gray's signed release list. It then verifies the receipt under the keys
that attestation shows. When a provider's confidential VM served the answer, it checks that VM's attestation and the
receipt the VM made, with every change Gray declared to the request and the answer.

gray-lane-verify is licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`).

This tree holds exactly the 165 files that the published bundle `gray-lane-verify-1.7.1.mjs` and the image
`ghcr.io/gray-ai-dev/gray-lane-verify:1.7.1` are built from, at the paths they have in Gray's repository, plus the files Gray
writes for each release: this README, `SOURCE.json`, `rebuild.sh`, `.gitignore`, `LICENSE` and `NOTICE`. Tests,
documentation and Gray's other services are not included. Each release is one commit in this repository, and its
parent is the release published before it, so `git diff <previous tag> v1.7.1-7f264111a618` shows the code that changed between
the two.

## Get it

| Form | Where |
|-|-|
| One file for Node 22 or later, no install step | `https://releases.usefallback.com/lane-verify/1.7.1/gray-lane-verify-1.7.1.mjs`, with `.sha256` and `.sigstore.json` beside it, and `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES` in the same directory |
| Container image | `ghcr.io/gray-ai-dev/gray-lane-verify:1.7.1`, also tagged `7f264111a618`; the same three files are in `/opt/gray-lane-verify/` |
| Source | this repository, tag `v1.7.1-7f264111a618` |

Gray signs the file and the image with its release key, the cosign public key in
`deploy/relay/kit/keys/gray-assistant-cosign.pub`. Its SHA-256 is
`1d769d4b6c09246f16e4a0cd5d237e006beec9544dae0fba6ec856d9c23433be`, and the same key is in Gray's other public
repositories. Check a download before you run it:

```sh
cosign verify-blob --key gray-assistant-cosign.pub \
  --bundle gray-lane-verify-1.7.1.mjs.sigstore.json gray-lane-verify-1.7.1.mjs
deploy/relay/kit/cosign.sh verify-file gray-lane-verify-1.7.1.mjs
deploy/relay/kit/cosign.sh verify-image ghcr.io/gray-ai-dev/gray-lane-verify:1.7.1
```

`cosign.sh verify-image` prints the commit the image was signed as built from: it is `7f264111a6185ce0f01cdea77ab0a4404a12d9bf`.
`node gray-lane-verify-1.7.1.mjs --version` prints the same commit.

## Run it

```sh
export GRAY_API_KEY=...   # the key that made the request; read from the environment, never printed
node gray-lane-verify-1.7.1.mjs check <x-receipt-id> --request request.json --response response.bin
docker run --rm -v "$PWD:/work" -e GRAY_API_KEY ghcr.io/gray-ai-dev/gray-lane-verify:1.7.1 \
  check <x-receipt-id> --request request.json --response response.bin
```

`--request` is the exact body you sent, and `--response` the raw bytes you received (optional). When the answer
carried an `x-gray-lane-origin` header, pass it as `--lane-origin`. The command prints each check, a summary of what
they covered, `VERDICT: PASS` or `VERDICT: FAIL`, and one JSON line for scripts. It exits 0 when every check passed,
1 when one failed or the entry gave no receipt, and 2 on a usage or I/O error.

The entry keeps a receipt in memory for an hour after the answer ends, with the records of each attempt a provider's
VM served (`/v1/aci/receipts/<id>/peers/<n>`). To check later, save the receipt while the entry holds it and pass it
as `--receipt <file>`. The command still asks the entry for each attempt's record. When the entry answers
`404 receipt_not_found` for one after the receipt's signed `served_at` plus 7 500 s (an hour for the longest request,
the hour the entry keeps a receipt, and 300 s for clock difference), the line is `EXPIRED peer:<n>:fetch`: that
attempt was not checked. If no check failed, the command prints `VERDICT: EXPIRED` and exits 4, and the JSON line has
`ok: false` and `expired_peers`. A failed check is still `VERDICT: FAIL`, exit 1. Before that time the same answer is
a failure, as is any other answer at any time. A receipt id alone carries no signed time, so a receipt the entry no
longer gives is a failure. Versions before 1.7.1 print `VERDICT: FAIL` for an expired record.

When you leave before reading the whole answer, the entry signs `served_as: client_left`, and the receipt's
`events_sha256` (or, for a buffered answer, `body_sha256`) covers everything the entry queued for you. A `--response`
file that holds less cannot reproduce that digest. From 1.7.1 the command then prints
`PARTIAL response_events_sha256` (or `response_body_sha256`), says that the entry recorded `client_left` and that the
bytes you hold are shorter than what it queued, and, if no check failed, prints `VERDICT: PARTIAL` and exits 5. The
JSON line has `ok: false` and `partial_response`. The raw `body_hash` is not compared on such a receipt, since it also
covers the entry's keep-alive comments. Bytes that end the answer (`data: [DONE]`, `response.completed`,
`response.incomplete`, `response.failed`, `message_stop`, or a whole JSON body) and do not match are still a failure.
A failed check is `VERDICT: FAIL`, exit 1, and `PARTIAL` comes before `EXPIRED`. Versions before 1.7.1 print
`VERDICT: FAIL` for a response you left early.

A release list counts for a day after it was signed, and after that only while the freshness document Gray publishes
beside it (`release-list.freshness.json`, renewed every half hour) vouches for its exact bytes; the command reads both.
To name the stack list yourself, pass `--allow-stack <file or URL>`: the command then reads the document beside it.
Pass `--allow-stack-freshness <file or URL>` when the document is not beside the list under that name. Versions before
1.2.1 read it only when that flag names it, so with them a stack list older than a day fails as `list_stale` without
`--allow-stack-freshness https://releases.usefallback.com/lane/stack/release-list.freshness.json`.

A request sent to Gray's API address (`https://api.usefallback.com`) instead of the entry reaches the confidential VM
through Gray's API, where the client's TLS ends at Cloudflare. Its receipt says so (`api_version` `aci/1+gray-api` and
`arrival: "gray_api"`, both signed). The command then runs every check and fails one more, `client_connection`, and
when that is the only failure prints `VERDICT: VALID, NOT END TO END: arrived through Gray's API` and exits 3: the
receipt is genuine, and the leg from the client to the VM is not covered. Send the request to the entry to have it
covered. Version 1.0.0 fails such a receipt (`receipt_version`).

A request may state its routing preference in the body (`provider`, as at Gray's API). The entry takes it out before it
forwards the body, a declared rewrite the receipt names (`remove_member /provider`; for a provider's VM, on the
attempt's `peer.forwarded`), and the command replays it. Where the preference asks for verifiable routes
(`"verifiable": true`), it also checks that no attempt the receipt records was at a provider's own API
(`routing_preference`). Versions before 1.2.0 have no such rule and fail these receipts.

For a provider's own API, the entry may translate a request onto another text API (Chat Completions, Responses,
Messages, Gemini) and the answer back. The receipt names the translation (`request.translated`) by id, and the
command replays it with that translation's code: the forwarded body must be exactly the translation of your bytes
with Gray's declared ops. The entry signs `gray-lane-translation-v2`; receipts of earlier entries name
`gray-lane-translation-v1`, which the command replays with a frozen copy of the code they ran. A receipt is replayed
under the id it names and no other. The `translation` line names the id, and with the machine line's `translation`
the two APIs and the fields the translated request does not carry. The answer's translation back is not replayed: the
receipt hashes the answer as you received it. Versions before 1.3.0 fail these receipts, and versions before 1.6.0
fail one that names `gray-lane-translation-v2`.

The command also verifies a receipt of embeddings, rerank, image generations and edits, speech, transcriptions,
translations, videos and System One, which the entry serves for a provider's own API. Gray's changes to such a request
are declared under `gray-lane-rewrites-v2`: the provider's name for the model, and the removal of the fields that name
the end user or state a routing preference. When the request is a `multipart/form-data` form, the changes are the ops
`set_form_field` and `remove_form_field`, replayed on the bytes you sent: every other byte, each file included, must
be forwarded as it came. A form is read by the boundary of its own first line, so the command needs the body you sent
and nothing about its headers. Versions before 1.4.0 fail these receipts.

On a route to ChatGPT's Codex backend, which refuses a Responses `input` that is a string, the entry sends your string
as one user message, `[{"type":"message","role":"user","content":[{"type":"input_text","text":<your string>}]}]`,
with its bytes as you wrote them. The receipt declares this as `wrap_input_text /input` under
`gray-lane-rewrites-v3`, with no value, and the command replays it on the bytes you sent. Versions before 1.7.0 fail
these receipts.

On the Responses API, on a route that sends `store: false` upstream, the entry keeps a conversation itself: unless
you send `store: false`, it seals each turn's items in its confidential VM for 2 hours and, on a later turn, expands
`previous_response_id` and `item_reference` inputs into inline `input` before it forwards the body. On a reasoning
model it may also add `"reasoning.encrypted_content"` to `include`. The receipt records this as
`request.continuation_expanded`, with the SHA-256 of the expanded body and no text of the earlier turns. The command
checks the event against the bytes you sent (`continuation_expanded`) and, when Gray declared no other change, the
forwarded body against that hash. The earlier turns stay sealed in the entry, so it does not replay the expansion:
where Gray declared a change after it, the lines that would compare those bytes are skipped and say so.
The command also verifies a receipt of a token count (`/v1/messages/count_tokens`, Gemini's `:countTokens`). Versions
before 1.5.0 fail these receipts.

## What one check does, and where its source is

| Step | Source |
|-|-|
| the command line, the receipt fetch (`503 receipt_pending` and `Retry-After`, `x-gray-lane-origin`), the verdict and exit code | `workers/packages/lane-verify/src/node/cli.ts`, `workers/packages/lane-verify/src/lane-origin.ts` |
| Gray's entry: its origin, where its release lists are published, the release and freshness keys built in | `workers/packages/lane-verify/src/node/entries.ts` |
| the signed release list and its freshness document | `workers/packages/lane-verify/src/release-list.ts`, `workers/packages/lane-verify/src/release-freshness.ts` |
| remote attestation: the Intel TDX quote (DCAP, collateral from Intel PCS), the boot's event log, the compose and OS image against the list, the TLS key of the connection | `workers/packages/lane-verify/src/attestation.ts`, `workers/packages/lane-verify/src/dcap.ts`, `workers/packages/lane-verify/src/node/dcap.ts`, `workers/packages/lane-verify/src/dstack.ts` |
| the receipt: its signature under the attested keyset, the request and answer hashes, Gray's declared changes | `workers/packages/lane-verify/src/receipt.ts`, `workers/packages/attest/src/`, `workers/packages/lane/src/` |
| a translated request: the replay of the translation the entry ran | `workers/packages/lane/src/translation.ts`, `workers/packages/protocol/src/translate/` |
| a request of a standard API, JSON or a form: the replay of Gray's declared changes | `workers/packages/lane/src/api-changes.ts`, `workers/packages/lane/src/form.ts`, `workers/packages/lane/src/policy.ts` |
| a provider's confidential VM: its attestation, the image it runs, its own receipt and how it ties to the entry's | `workers/packages/lane-verify/src/peer-receipt.ts`, `workers/packages/lane-verify/src/peer.ts`, `workers/packages/lane-verify/src/stack-boot.ts` |
| the bundle and the image | `deploy/lane-verify/bundle.mjs`, `deploy/lane-verify/Dockerfile`, built and signed by `deploy/lane-verify/release.sh` |

## What to review

> Review this tree (and `git diff <the tag you run now> v1.7.1-7f264111a618`) for any way gray-lane-verify could print
> `VERDICT: PASS` or exit 0 for an answer whose receipt, attestation or release list does not check out, or for one
> whose receipt says it arrived through Gray's API (`aci/1+gray-api`), or could send
> the API key anywhere other than the entry origin the user named or a replica that origin's answer named. Trace:
> (1) where the key is read (`GRAY_API_KEY`) and every request that carries it; (2) every network request and the
> host it reaches: the entry, Gray's releases host for the lists, Intel PCS or the `--pccs` URL for quote collateral;
> (3) what decides the verdict: which checks can fail it, and whether a skipped check can make it pass; (4) the keys
> built into `workers/packages/lane-verify/src/node/entries.ts`, which decide which release lists are accepted.
> Report each place the key is logged, stored or sent elsewhere, and each path to a pass that skips a check.

The tool writes nothing to disk. It prints check lines and hashes, never request or answer content and never the key.

## Rebuild

`./rebuild.sh` builds the bundle and then the image for one platform (linux/amd64 by default, `PLATFORM=linux/arm64`
for the other) with the build commands of `deploy/lane-verify/release.sh`. It prints `rebuild.sh: bundle sha256:…`,
which must equal the published `.sha256`, `rebuild.sh: notices sha256:…`, the published `THIRD_PARTY_NOTICES`', and
`rebuild.sh: manifest sha256:…`, which must equal the published image's
manifest for the same platform: `docker buildx imagetools inspect --raw ghcr.io/gray-ai-dev/gray-lane-verify:1.7.1` lists one
manifest per platform. Gray rebuilds this way from this tree before it publishes a tag, and does not publish when
any of them differs.

## What is not reproducible yet

- The Node base image is used as its project publishes it, pinned by digest in `deploy/lane-verify/Dockerfile`.
- The image index's digest: Gray attaches a provenance attestation with the build's own times. Compare the manifest
  of each platform, not the index.

## License

Licensed under the Apache License, Version 2.0: see `LICENSE` and `NOTICE`. You may use, modify and redistribute this
source and the tool built from it under those terms.

The bundle and the image also contain code from npm packages, each under its own permissive license (MIT, ISC,
BSD-2-Clause, BSD-3-Clause, 0BSD or Apache-2.0); `deploy/lane-verify/bundle.mjs` refuses any other. Their license
and notice texts are in `THIRD_PARTY_NOTICES`, published beside the file and in the image, and at the end of the
file itself, where the packages' own license comments are kept too.
