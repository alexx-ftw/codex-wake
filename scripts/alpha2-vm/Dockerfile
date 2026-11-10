FROM rust:1.98.0-trixie@sha256:8aea3a845c48caac4091a8d0e6494d213061f8f014dc2f5a5f1a88a1a8c9f301
WORKDIR /work
COPY scripts/alpha2-vm/dependencies.env /deps.env
RUN set -eu; . /deps.env; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf 'deb [check-valid-until=no] %s trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d; \
    curl -fL --retry 3 "$DEBIAN_SNAPSHOT/dists/trixie/main/binary-amd64/Packages.xz" -o /tmp/Packages.xz; \
    printf '%s  /tmp/Packages.xz\n' "$PACKAGES_SHA256" | sha256sum -c -; \
    apt-get update; \
    apt-get install -y --no-install-recommends clang libbpf-dev bpftool systemd dbus \
      bubblewrap cpio zstd ripgrep nodejs strace libkmod2 libseccomp2 qemu-system-x86 \
      xz-utils bzip2 lz4; \
    dpkg-query -W -f='${binary:Package}\t${Version}\n' > /packages.tsv; \
    rm -rf /var/lib/apt/lists/*
COPY . /work
ENV RUSTUP_TOOLCHAIN=1.98.0
RUN bash scripts/alpha2-vm/build.sh
WORKDIR /output
ENTRYPOINT ["bash", "/work/scripts/alpha2-vm/run.sh"]
