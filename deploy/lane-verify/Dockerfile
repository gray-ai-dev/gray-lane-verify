# gray-lane-verify as a container image: a pinned Node, the one-file bundle deploy/lane-verify/bundle.mjs makes, and its
# licenses, nothing else. Its build context holds this file, that bundle (named gray-lane-verify.mjs), the
# THIRD_PARTY_NOTICES bundle.mjs writes beside it, and deploy/lane-verify/LICENSE and NOTICE; release.sh beside this
# file and the published source's rebuild.sh make the context and build it the same way:
#
#   docker buildx build -f Dockerfile --build-arg SOURCE_DATE_EPOCH=<commit time> \
#     --output type=oci,dest=image.tar,rewrite-timestamp=true <context>
#
# Run it with the files it reads mounted at /work, and the key that made the request in the environment:
#
#   docker run --rm -v "$PWD:/work" -e GRAY_API_KEY ghcr.io/gray-ai-dev/gray-lane-verify:<version> \
#     check <receipt id> --request request.json
#
# No RUN step: the image is the base image's layers, one layer with the bundle and its licenses, and the working
# directory, the same for every platform.
ARG NODE_BASE=node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
FROM ${NODE_BASE}

LABEL org.opencontainers.image.title="gray-lane-verify" \
      org.opencontainers.image.description="Checks a Gray answer's signed receipt and the remote attestation of the confidential VMs that served it" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY gray-lane-verify.mjs LICENSE NOTICE THIRD_PARTY_NOTICES /opt/gray-lane-verify/
USER node
WORKDIR /work
ENTRYPOINT ["node", "/opt/gray-lane-verify/gray-lane-verify.mjs"]
