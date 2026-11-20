#!/usr/bin/env bash
# Rebuilds gray-lane-verify 1.2.0 (v1.2.0-2b567293024d) from this tree with the build commands of deploy/lane-verify/release.sh
# (the script Gray publishes with): the one-file bundle, then the image for one platform. Prints the bundle's sha256 and
# the platform's OCI manifest digest, and the THIRD_PARTY_NOTICES' sha256. Compare them with what Gray published
# (README.md, "Rebuild"):
#
#   ./rebuild.sh                              # linux/amd64
#   PLATFORM=linux/arm64 ./rebuild.sh
#
# The bundle: `npm ci` in workers/ from its lockfile, then deploy/lane-verify/bundle.mjs. The image: a context of
# deploy/lane-verify/Dockerfile, that bundle, its THIRD_PARTY_NOTICES and deploy/lane-verify/LICENSE and NOTICE, built --no-cache with every time fixed to the commit's
# (SOURCE_DATE_EPOCH, rewrite-timestamp) and exported as an OCI layout.
#
# Needs node 22 or later, npm, and docker with buildx and a builder that can export an OCI layout. Network: npm's
# registry (npm ci) and Docker Hub (the pinned Node base image).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
commit=2b567293024dfa2b49db874d45016021b0d077be
epoch=1795166858
version=1.2.0
platform=${PLATFORM:-linux/amd64}
out="$here/rebuild"
command -v node >/dev/null 2>&1 || { echo "rebuild.sh: node is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "rebuild.sh: docker is required" >&2; exit 2; }
sha256() { (command -v sha256sum >/dev/null && sha256sum "$1" || shasum -a 256 "$1") | cut -d' ' -f1; }
rm -rf "$out" && mkdir -p "$out/context"
echo "rebuild.sh: gray-lane-verify $version from $commit: npm ci in workers/"
(cd "$here/workers" && npm ci --ignore-scripts --no-audit --no-fund >"$out/npm.log" 2>&1) || { tail -n 30 "$out/npm.log" >&2; exit 1; }
node "$here/deploy/lane-verify/bundle.mjs" "$here/workers" "$out/bundle" --commit "$commit" >"$out/bundle.log" 2>&1 || { tail -n 30 "$out/bundle.log" >&2; exit 1; }
bundle="$out/bundle/gray-lane-verify-$version.mjs"
echo "rebuild.sh: bundle $bundle"
echo "rebuild.sh: bundle sha256:$(sha256 "$bundle")"
echo "rebuild.sh: notices sha256:$(sha256 "$out/bundle/THIRD_PARTY_NOTICES")"
(umask 022 && cp "$here/deploy/lane-verify/Dockerfile" "$out/context/Dockerfile" && cp "$bundle" "$out/context/gray-lane-verify.mjs" \
  && cp "$out/bundle/THIRD_PARTY_NOTICES" "$here/deploy/lane-verify/LICENSE" "$here/deploy/lane-verify/NOTICE" "$out/context/" \
  && chmod 0644 "$out/context/gray-lane-verify.mjs" "$out/context/THIRD_PARTY_NOTICES" "$out/context/LICENSE" "$out/context/NOTICE")
echo "rebuild.sh: building the image for $platform"
BUILDX_GIT_INFO=0 docker buildx build --no-cache --platform "$platform" -f "$out/context/Dockerfile" \
  --provenance=false --build-arg "SOURCE_DATE_EPOCH=$epoch" \
  --label "org.opencontainers.image.revision=$commit" --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.source=https://github.com/gray-ai-dev/gray-lane-verify" \
  --annotation "manifest:org.opencontainers.image.licenses=Apache-2.0" \
  --annotation "manifest:org.opencontainers.image.revision=$commit" \
  --annotation "manifest:org.opencontainers.image.version=$version" \
  --annotation "manifest:org.opencontainers.image.source=https://github.com/gray-ai-dev/gray-lane-verify" \
  --output "type=oci,dest=$out/image.tar,rewrite-timestamp=true" "$out/context" >"$out/build.log" 2>&1 || { tail -n 30 "$out/build.log" >&2; exit 1; }
digest=$(tar -xOf "$out/image.tar" index.json | node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{const i=JSON.parse(s);if(i.manifests.length!==1){process.exit(1)}process.stdout.write(i.manifests[0].digest)})')
echo "rebuild.sh: commit $commit"
echo "rebuild.sh: oci $out/image.tar"
echo "rebuild.sh: manifest $digest"
