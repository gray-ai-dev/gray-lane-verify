# gray-lane-verify 1.2.0 (v1.2.0-2b567293024d)

The source of `gray-lane-verify` 1.2.0, built from Gray's commit `2b567293024dfa2b49db874d45016021b0d077be`. gray-lane-verify checks one answer
from Gray's confidential entry in one command. It fetches the answer's signed receipt and checks the remote attestation
of the confidential VM that signed it against Gray's signed release list. It then verifies the receipt under the keys
that attestation shows. When a provider's confidential VM served the answer, it checks that VM's attestation and the
receipt the VM made, with every change Gray declared to the request and the answer.

gray-lane-verify is licensed under the Apache License, Version 2.0 (`LICENSE`, `NOTICE`).

This tree holds exactly the 157 files that the published bundle `gray-lane-verify-1.2.0.mjs` and the image
`ghcr.io/gray-ai-dev/gray-lane-verify:1.2.0` are built from, at the paths they have in Gray's repository, plus the files Gray
writes for each release: this README, `SOURCE.json`, `rebuild.sh`, `.gitignore`, `LICENSE` and `NOTICE`. Tests,
documentation and Gray's other services are not included. Each release is one commit in this repository, and its
parent is the release published before it, so `git diff <previous tag> v1.2.0-2b567293024d` shows the code that changed between
the two.

## Get it

| Form | Where |
|-|-|
| One file for Node 22 or later, no install step | `https://releases.usefallback.com/lane-verify/1.2.0/gray-lane-verify-1.2.0.mjs`, with `.sha256` and `.sigstore.json` beside it, and `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES` in the same directory |
| Container image | `ghcr.io/gray-ai-dev/gray-lane-verify:1.2.0`, also tagged `2b567293024d`; the same three files are in `/opt/gray-lane-verify/` |
| Source | this repository, tag `v1.2.0-2b567293024d` |

Gray signs the file and the image with its release key, the cosign public key in
`deploy/relay/kit/keys/gray-assistant-cosign.pub`. Its SHA-256 is
`1d769d4b6c09246f16e4a0cd5d237e006beec9544dae0fba6ec856d9c23433be`, and the same key is in Gray's other public
repositories. Check a download before you run it:

```sh
cosign verify-blob --key gray-assistant-cosign.pub \
  --bundle gray-lane-verify-1.2.0.mjs.sigstore.json gray-lane-verify-1.2.0.mjs
deploy/relay/kit/cosign.sh verify-file gray-lane-verify-1.2.0.mjs
deploy/relay/kit/cosign.sh verify-image ghcr.io/gray-ai-dev/gray-lane-verify:1.2.0
```

`cosign.sh verify-image` prints the commit the image was signed as built from: it is `2b567293024dfa2b49db874d45016021b0d077be`.
`node gray-lane-verify-1.2.0.mjs --version` prints the same commit.

## Run it

```sh
export GRAY_API_KEY=...   # the key that made the request; read from the environment, never printed
node gray-lane-verify-1.2.0.mjs check <x-receipt-id> --request request.json --response response.bin
docker run --rm -v "$PWD:/work" -e GRAY_API_KEY ghcr.io/gray-ai-dev/gray-lane-verify:1.2.0 \
  check <x-receipt-id> --request request.json --response response.bin
```

`--request` is the exact body you sent, and `--response` the raw bytes you received (optional). When the answer
carried an `x-gray-lane-origin` header, pass it as `--lane-origin`. The command prints each check, a summary of what
they covered, `VERDICT: PASS` or `VERDICT: FAIL`, and one JSON line for scripts. It exits 0 when every check passed,
1 when one failed or the entry gave no receipt, and 2 on a usage or I/O error.

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

## What one check does, and where its source is

| Step | Source |
|-|-|
| the command line, the receipt fetch (`503 receipt_pending` and `Retry-After`, `x-gray-lane-origin`), the verdict and exit code | `workers/packages/lane-verify/src/node/cli.ts`, `workers/packages/lane-verify/src/lane-origin.ts` |
| Gray's entry: its origin, where its release lists are published, the release and freshness keys built in | `workers/packages/lane-verify/src/node/entries.ts` |
| the signed release list and its freshness document | `workers/packages/lane-verify/src/release-list.ts`, `workers/packages/lane-verify/src/release-freshness.ts` |
| remote attestation: the Intel TDX quote (DCAP, collateral from Intel PCS), the boot's event log, the compose and OS image against the list, the TLS key of the connection | `workers/packages/lane-verify/src/attestation.ts`, `workers/packages/lane-verify/src/dcap.ts`, `workers/packages/lane-verify/src/node/dcap.ts`, `workers/packages/lane-verify/src/dstack.ts` |
| the receipt: its signature under the attested keyset, the request and answer hashes, Gray's declared changes | `workers/packages/lane-verify/src/receipt.ts`, `workers/packages/attest/src/`, `workers/packages/lane/src/` |
| a provider's confidential VM: its attestation, the image it runs, its own receipt and how it ties to the entry's | `workers/packages/lane-verify/src/peer-receipt.ts`, `workers/packages/lane-verify/src/peer.ts`, `workers/packages/lane-verify/src/stack-boot.ts` |
| the bundle and the image | `deploy/lane-verify/bundle.mjs`, `deploy/lane-verify/Dockerfile`, built and signed by `deploy/lane-verify/release.sh` |

## What to review

> Review this tree (and `git diff <the tag you run now> v1.2.0-2b567293024d`) for any way gray-lane-verify could print
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
manifest for the same platform: `docker buildx imagetools inspect --raw ghcr.io/gray-ai-dev/gray-lane-verify:1.2.0` lists one
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
