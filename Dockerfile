# Keep this version in sync with rust-toolchain.toml and CI.
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build

ARG VCS_REF=unknown

WORKDIR /src
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN ROOKHOLD_GIT_REVISION="${VCS_REF}" cargo build --locked --release \
      -p coop-server -p coop-exec -p coop-attestation --bins

# Both the service image and private job rootfs use the same digest-pinned
# Debian base and immutable package snapshot. Package resolution therefore
# cannot drift between builds or between the outer launcher and job rootfs.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime-base
ARG DEBIAN_SNAPSHOT=20260826T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3 nodejs bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The namespace backend never receives the outer container root as its rootfs.
# This stage is copied into a separate, trusted tree used only for job pivots.
FROM runtime-base AS sandbox-rootfs
RUN install -d -m 0755 /.pivot_old /proc /dev /work /input /output \
    && install -d -m 1777 /tmp \
    && install -d -m 0755 /tmp/home

FROM sandbox-rootfs AS complete-sandbox-rootfs
COPY --from=build /src/target/release/rookhold-oci-init /usr/local/bin/rookhold-oci-init
COPY --from=build /src/target/release/coop-oci-init /usr/local/bin/coop-oci-init

FROM runtime-base AS runtime

# The namespace bootstrap and seccomp policy are x86_64-only. Refuse to
# produce a production image whose platform cannot provide the documented
# containment boundary.
RUN test "$(dpkg --print-architecture)" = amd64

ARG VERSION=0.8.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Rookhold" \
      org.opencontainers.image.description="Audit-first execution gateway for AI agents" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sambai-dev/rookhold" \
      org.opencontainers.image.licenses="MIT"

# Interpreters exist both outside and inside the job rootfs. Jobs pivot into
# the private /opt/rookhold/rootfs tree before exec.
RUN install -d -o root -g root -m 0700 /data /var/lib/rookhold/jobs /opt/rookhold \
    && install -d -o root -g root -m 0700 \
      /run/rookhold-bootstrap /run/rookhold-runtime /run/rookhold-secrets \
    && install -d -o root -g root -m 0755 /opt/rookhold/rootfs

COPY --from=complete-sandbox-rootfs / /opt/rookhold/rootfs
COPY scripts/build-rootfs-manifest.py /tmp/build-rootfs-manifest.py
RUN python3 /tmp/build-rootfs-manifest.py /opt/rookhold/rootfs >/dev/null \
    && rm /tmp/build-rootfs-manifest.py
COPY --from=build /src/target/release/rookhold /usr/local/bin/rookhold
COPY --from=build /src/target/release/coop /usr/local/bin/coop
COPY --from=build /src/target/release/rookhold-sandbox-init /usr/local/bin/rookhold-sandbox-init
COPY --from=build /src/target/release/coop-sandbox-init /usr/local/bin/coop-sandbox-init
COPY --from=build /src/target/release/rookhold-verify /usr/local/bin/rookhold-verify
COPY --from=build /src/target/release/coop-verify /usr/local/bin/coop-verify
COPY --chmod=0755 scripts/container-entrypoint.sh /usr/local/bin/rookhold-container-entrypoint
COPY --chmod=0755 scripts/container-entrypoint.sh /usr/local/bin/coop-container-entrypoint

ENV ROOKHOLD_ENV=production \
    ROOKHOLD_ADDR=0.0.0.0:7300 \
    ROOKHOLD_DB=/data/rookhold.db \
    ROOKHOLD_JOBS_ROOT=/var/lib/rookhold/jobs \
    ROOKHOLD_ROOTFS=/opt/rookhold/rootfs \
    ROOKHOLD_SANDBOX_HELPER=/usr/local/bin/rookhold-sandbox-init

EXPOSE 7300
VOLUME ["/data"]

# Container health includes process/store readiness. Containment posture still
# lives on the authenticated status surface; see docs/operations.md.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7300/readyz', timeout=2).read()"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/rookhold-container-entrypoint"]
CMD ["/usr/local/bin/rookhold"]
