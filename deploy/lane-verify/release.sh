#!/usr/bin/env bash
# Builds one release of gray-lane-verify from this checkout's HEAD: the one-file bundle (bundle.mjs beside this file)
# and the container image (Dockerfile beside it), both from `git archive` of the commit. Then signs the bundle, pushes
# the image tagged with the version and the commit, and signs the image, all with Gray's release key. Run it on the
# build box from a clean checkout of the commit to publish (scripts/ops/box-run.sh <commit> -- deploy/lane-verify/release.sh
# ...). deploy/lane-verify/publish.sh then publishes the source and uploads the bundle.
#
#   deploy/lane-verify/release.sh --repository <registry>/<path> --out <directory>
#       [--username <user> --password-file <file>] [--sign-key-file <file> [--sign-password-file <file>]]
#       [--platforms linux/amd64,linux/arm64] [--docker <docker command>] [--dry-run]
#
#   --repository      where to push, e.g. ghcr.io/gray-ai-dev/gray-lane-verify (no default)
#   --out             where the bundle goes: gray-lane-verify-<version>.mjs, its .sha256 (`<hex>  <file name>`) and,
#                     signed, its .sigstore.json; LICENSE, NOTICE and THIRD_PARTY_NOTICES, which publish.sh uploads
#                     beside it; and release.txt, the lines publish.sh takes. An empty or new directory.
#   --username        the registry user the push token belongs to
#   --password-file   a file holding the push token alone; read once into `docker login --password-stdin` under a
#                     throwaway DOCKER_CONFIG that is deleted afterwards. Never printed.
#   --sign-key-file   Gray's release key: cosign's private key file, a regular file of mode 0600, whose public half must
#                     be deploy/relay/kit/keys/gray-assistant-cosign.pub at the commit (checked before the build).
#                     Required to push. Copy it to the box for the release only.
#   --sign-password-file  the key's password alone in a 0600 file, read into COSIGN_PASSWORD only; none: empty
#   --platforms       default linux/amd64,linux/arm64 (the Dockerfile has no RUN step: no emulation)
#   --docker          the docker command, when docker is not on the PATH as `docker`; default $DOCKER, else docker
#   --dry-run         build the bundle and the image for every platform, print the bundle's sha256, each platform's
#                     manifest digest and the index that would be pushed; push, sign and log in to nothing
#
# The image's org.opencontainers.image.source label and annotation are the public source repository images.json names
# for gray-lane-verify at the commit (rebuild.sh sets the same). The version is workers/packages/lane-verify/VERSION at
# the commit; the image is tagged `<version>` and `<commit, 12>`,
# and a version already in the registry is refused (a version is published once). The bundle is
# gray-lane-verify-<version>.mjs; the image holds those same bytes at /opt/gray-lane-verify/gray-lane-verify.mjs, beside
# LICENSE, NOTICE and THIRD_PARTY_NOTICES, in the one layer the Dockerfile copies above the base image. The image is labelled and annotated
# org.opencontainers.image.licenses=Apache-2.0.
#
# One build path with the published source's rebuild.sh (scripts/ops/public-source/templates/gray-lane-verify): `npm ci`
# in the archive's workers/ from its lockfile, bundle.mjs there, and the image built --no-cache from a context of the
# Dockerfile and the bundle alone, every time fixed to the commit's (SOURCE_DATE_EPOCH, rewrite-timestamp), exported as
# an OCI layout with rebuild.sh's exporter options; that layout is what is pushed (`docker buildx imagetools create`
# from oci-layout://), and the pushed index must have the layout's digest. As for gray-assistant
# (deploy/relay/image/release.sh), the index carries a provenance attestation with the build's own times, so readers
# compare each platform's manifest, which rebuild.sh reproduces.
set -euo pipefail
umask 077
die() { echo "release.sh: $*" >&2; exit 2; }
repository="" out="" username="" password_file="" sign_key_file="" sign_password_file="" platforms=linux/amd64,linux/arm64 docker=${DOCKER:-docker} dry_run=0
while [ $# -gt 0 ]; do
  case $1 in
    --repository) repository=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --username) username=${2:?}; shift 2 ;;
    --password-file) password_file=${2:?}; shift 2 ;;
    --sign-key-file) sign_key_file=${2:?}; shift 2 ;;
    --sign-password-file) sign_password_file=${2:?}; shift 2 ;;
    --platforms) platforms=${2:?}; shift 2 ;;
    --docker) docker=${2:?}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h | --help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0"; exit 0 ;;
    *) die "unknown argument $1 (--help lists the flags)" ;;
  esac
done
[ -n "$repository" ] || die "--repository is required (e.g. ghcr.io/gray-ai-dev/gray-lane-verify)"
[[ $repository =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]] || die "--repository must be <registry>/<path> in lower case, without a tag"
[ -n "$out" ] || die "--out <directory> is required"
if [ -e "$out" ]; then
  [ -d "$out" ] && [ -z "$(ls -A "$out")" ] || die "--out $out must be an empty or new directory"
fi
if [ "$dry_run" = 0 ]; then
  [ -n "$username" ] || die "--username is required"
  [ -n "$password_file" ] || die "--password-file is required"
  [ -f "$password_file" ] && [ ! -L "$password_file" ] || die "--password-file must be a regular file"
  [ -n "$sign_key_file" ] || die "--sign-key-file is required: a release is signed with Gray's release key"
fi
secret_file() { # <flag> <file>: a regular file of mode 0600
  [ -f "$2" ] && [ ! -L "$2" ] || die "$1 must be a regular file"
  local mode
  mode=$(stat -c %a "$2" 2>/dev/null || stat -f %Lp "$2")
  [ "$mode" = 600 ] || die "$1 must have mode 0600 (it has $mode)"
}
if [ -n "$sign_key_file" ]; then secret_file --sign-key-file "$sign_key_file"; fi
if [ -n "$sign_password_file" ]; then
  secret_file --sign-password-file "$sign_password_file"
  COSIGN_PASSWORD=$(cat "$sign_password_file")
  export COSIGN_PASSWORD
fi
read -r -a dk <<<"$docker"
command -v node >/dev/null 2>&1 || die "node is required (box-run.sh puts the box's on the PATH)"
command -v npm >/dev/null 2>&1 || die "npm is required"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ -z "$(git -C "$root" status --porcelain --untracked-files=no)" ] || die "the checkout has uncommitted changes; release a commit"
sha=$(git -C "$root" rev-parse HEAD)
tag="${sha:0:12}"
registry=${repository%%/*}
sha256() { (command -v sha256sum >/dev/null && sha256sum "$1" || shasum -a 256 "$1") | cut -d' ' -f1; }

cosign_sh="$root/deploy/relay/kit/cosign.sh"
git -C "$root" cat-file -e "$sha:deploy/relay/kit/keys/gray-assistant-cosign.pub" 2>/dev/null \
  || die "deploy/relay/kit/keys/gray-assistant-cosign.pub is not in $tag"
# The key is checked now, not after a build of several minutes.
if [ -n "$sign_key_file" ]; then "$cosign_sh" check-key "$sign_key_file" || die "--sign-key-file is not Gray's release key"; fi

version=$(git -C "$root" show "$sha:workers/packages/lane-verify/VERSION" 2>/dev/null | tr -d '[:space:]')
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] \
  || die "workers/packages/lane-verify/VERSION at $tag holds no semantic version"
name="gray-lane-verify-$version.mjs"
image="$repository:$version"

work=$(mktemp -d "${TMPDIR:-/tmp}/gray-lane-verify-release.XXXXXX")
# The login lives in this throwaway config only; it is logged out and deleted however the script ends, with the
# archive and the OCI layout. Nothing is left in the local image store.
export DOCKER_CONFIG="$work/docker"
mkdir -p "$DOCKER_CONFIG"
export BUILDX_CONFIG="${BUILDX_CONFIG:-$HOME/.docker/buildx}"
trap '"${dk[@]}" logout "$registry" >/dev/null 2>&1; rm -rf "$work" 2>/dev/null || true' EXIT
cosign_config="$work/cosign"
mkdir -p "$cosign_config"
if [ "$dry_run" = 0 ]; then
  "${dk[@]}" login "$registry" --username "$username" --password-stdin <"$password_file" >/dev/null \
    || die "docker login to $registry failed"
  DOCKER_CONFIG="$cosign_config" "$("$cosign_sh" path)" login "$registry" --username "$username" --password-stdin \
    <"$password_file" >/dev/null 2>&1 || die "cosign login to $registry failed"
fi
# A version is published once: refuse a version tag the registry already has.
if "${dk[@]}" buildx imagetools inspect "$image" >/dev/null 2>&1; then
  die "$image is already in the registry; a version is published once: bump workers/packages/lane-verify/VERSION"
fi

# 1. The bundle, from the archive of the commit: the lockfile's packages, then bundle.mjs.
src="$work/src"
mkdir -p "$src"
(umask 022 && git -C "$root" -c tar.umask=0022 archive "$sha" | tar -x -C "$src") || die "could not write $tag into $src"
echo "release.sh: gray-lane-verify $version from $tag: npm ci in workers/"
(cd "$src/workers" && npm ci --ignore-scripts --no-audit --no-fund >"$work/npm.log" 2>&1) || { tail -n 20 "$work/npm.log" >&2; die "npm ci failed"; }
node "$src/deploy/lane-verify/bundle.mjs" "$src/workers" "$work/bundle" --commit "$sha" >"$work/bundle.log" 2>&1 \
  || { tail -n 20 "$work/bundle.log" >&2; die "bundle.mjs failed"; }
grep '^bundle.mjs: bundled ' "$work/bundle.log" | sed 's/^bundle.mjs:/release.sh:/' || true
bundle="$work/bundle/$name"
[ -f "$bundle" ] || die "bundle.mjs wrote no $name"
[ -f "$work/bundle/THIRD_PARTY_NOTICES" ] || die "bundle.mjs wrote no THIRD_PARTY_NOTICES"
sum=$(sha256 "$bundle")
notices_sum=$(sha256 "$work/bundle/THIRD_PARTY_NOTICES")
echo "release.sh: bundle $name sha256:$sum"
echo "release.sh: THIRD_PARTY_NOTICES sha256:$notices_sum"

# 2. The image, from a context of the Dockerfile and the bundle alone.
context="$work/context"
mkdir -p "$context"
(umask 022 && cp "$src/deploy/lane-verify/Dockerfile" "$context/Dockerfile" && cp "$bundle" "$context/gray-lane-verify.mjs" \
  && cp "$work/bundle/THIRD_PARTY_NOTICES" "$src/deploy/lane-verify/LICENSE" "$src/deploy/lane-verify/NOTICE" "$context/" \
  && chmod 0644 "$context/gray-lane-verify.mjs" "$context/THIRD_PARTY_NOTICES" "$context/LICENSE" "$context/NOTICE")
source_date_epoch=$(git -C "$root" log -1 --format=%ct "$sha")
source=$(git -C "$root" show "$sha:scripts/ops/public-source/images.json" | node -e 'let s="";process.stdin.on("data",(d)=>{s+=d}).on("end",()=>{process.stdout.write(JSON.parse(s).images["gray-lane-verify"]?.repository ?? "")})')
[[ $source =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "scripts/ops/public-source/images.json at $tag names no repository for gray-lane-verify"
labels=(--label "org.opencontainers.image.revision=$sha" --label "org.opencontainers.image.version=$version"
  --label "org.opencontainers.image.source=$source"
  --annotation "index,manifest:org.opencontainers.image.licenses=Apache-2.0"
  --annotation "index,manifest:org.opencontainers.image.revision=$sha"
  --annotation "index,manifest:org.opencontainers.image.version=$version"
  --annotation "index,manifest:org.opencontainers.image.source=$source")
layout="$work/oci"
mkdir -p "$layout"
echo "release.sh: building $image ($tag) for $platforms"
BUILDX_GIT_INFO=0 "${dk[@]}" buildx build --no-cache --platform "$platforms" -f "$context/Dockerfile" \
  --provenance=mode=max --sbom=true --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" "${labels[@]}" \
  --output "type=oci,dest=-,rewrite-timestamp=true" "$context" 2>"$work/build.log" | tar -x -C "$layout" \
  || { tail -n 30 "$work/build.log" >&2; die "the image build failed"; }
listing=$(node -e '
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const dir = process.argv[1];
const top = JSON.parse(fs.readFileSync(path.join(dir, "index.json"), "utf8"));
if (top.manifests?.length !== 1 || top.manifests[0].mediaType !== "application/vnd.oci.image.index.v1+json") process.exit(1);
const digest = top.manifests[0].digest;
const blob = fs.readFileSync(path.join(dir, "blobs", ...digest.split(":")));
if (`sha256:${crypto.createHash("sha256").update(blob).digest("hex")}` !== digest) process.exit(1);
console.log(digest);
for (const m of JSON.parse(blob).manifests) {
  if (m.annotations?.["vnd.docker.reference.type"] === "attestation-manifest") continue;
  console.log(`${m.platform.os}/${m.platform.architecture}${m.platform.variant ? `/${m.platform.variant}` : ""} ${m.digest}`);
}' "$layout") || die "the build's OCI layout holds no image index"
index=${listing%%$'\n'*}
[[ $index =~ ^sha256:[0-9a-f]{64}$ ]] || die "the build's OCI layout holds no image index"
amd64=""
while read -r platform digest; do
  echo "release.sh: $platform manifest $digest"
  [ "$platform" = linux/amd64 ] && amd64=$digest
done <<<"${listing#*$'\n'}"
echo "release.sh: index $index"

mkdir -p "$out"
cp "$bundle" "$out/$name"
printf '%s  %s\n' "$sum" "$name" >"$out/$name.sha256"
cp "$work/bundle/THIRD_PARTY_NOTICES" "$src/deploy/lane-verify/LICENSE" "$src/deploy/lane-verify/NOTICE" "$out/"
write_release() { # <image reference>
  {
    echo "version=$version"
    echo "commit=$sha"
    echo "bundle=$name"
    echo "bundle_sha256=sha256:$sum"
    echo "notices_sha256=sha256:$notices_sum"
    echo "image=$1"
    echo "manifest_linux_amd64=$amd64"
  } >"$out/release.txt"
}
source_ref="oci-layout://$layout@$index"
if [ "$dry_run" = 1 ]; then
  "${dk[@]}" buildx imagetools create --dry-run --tag "$image" --tag "$repository:$tag" "$source_ref" >"$work/push.json" \
    || die "imagetools create --dry-run failed"
  would=$(node -e 'const b = require("fs").readFileSync(0); const t = b[b.length - 1] === 10 ? b.subarray(0, -1) : b;
process.stdout.write(`sha256:${require("crypto").createHash("sha256").update(t).digest("hex")}`)' <"$work/push.json")
  [ "$would" = "$index" ] || die "imagetools create would push the index $would, not the layout's $index"
  write_release "$image@$index"
  echo "release.sh: dry run: nothing signed, logged in to or pushed; would sign $name and push $image and $repository:$tag as $index"
  echo "release.sh: wrote $out/$name, $out/$name.sha256 (unsigned), LICENSE, NOTICE, THIRD_PARTY_NOTICES and release.txt"
  exit 0
fi
"$cosign_sh" sign-blob "$sign_key_file" "$out/$name" >/dev/null || die "signing $name failed"
"$cosign_sh" verify-file "$out/$name" >&2 || die "signed $name, but the signature does not verify"
"${dk[@]}" buildx imagetools create --tag "$image" --tag "$repository:$tag" "$source_ref" >&2 || die "pushing the OCI layout to $image failed"
digest=$("${dk[@]}" buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || die "pushed, but could not read the digest; read it with: docker buildx imagetools inspect $image"
[ "$digest" = "$index" ] || die "pushed $image, but the registry's index is $digest, not the built layout's $index; not signed"
echo "pushed $image and $repository:$tag"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" sign-image "$sign_key_file" "$repository@$digest" "$sha" "$version" || die "pushed $image@$digest, but signing it failed"
DOCKER_CONFIG="$cosign_config" "$cosign_sh" verify-image "$repository@$digest" >&2 || die "signed $image@$digest, but the signature does not verify"
write_release "$image@$digest"
echo "signed $image@$digest"
echo "release.sh: wrote $out/$name, $out/$name.sha256, $out/$name.sigstore.json, LICENSE, NOTICE, THIRD_PARTY_NOTICES and release.txt"
echo "$image@$digest"
