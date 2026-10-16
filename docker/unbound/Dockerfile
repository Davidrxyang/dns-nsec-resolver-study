# Unbound 1.26.1 built from the NLnet Labs release tarball: NLnet Labs publishes no
# official Docker image. The tarball's signature was verified on 2026-10-16 with the
# "NLnet Labs releases signing key G2" (fingerprint 2310 1869 0C4D 903E F419 146A
# A144 323D EAAC DF45, as listed on https://nlnetlabs.nl/signing-keys/); the build
# re-checks the SHA-256 of that verified tarball.
ARG ALPINE=alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

FROM ${ALPINE} AS build
ARG VERSION=1.26.1
ARG SHA256=35a6dc0e425a9282c3426d9a3043144011bf0534aed4b73ab62c52aee0af1503
RUN apk add --no-cache build-base openssl-dev expat-dev libevent-dev
ADD https://nlnetlabs.nl/downloads/unbound/unbound-${VERSION}.tar.gz /src.tgz
RUN echo "${SHA256}  /src.tgz" | sha256sum -c - \
 && tar xzf /src.tgz && cd unbound-${VERSION} \
 && ./configure --prefix=/usr --sysconfdir=/etc --with-libevent \
 && make -j"$(nproc)" && make install DESTDIR=/out

FROM ${ALPINE}
RUN apk add --no-cache openssl expat libevent && adduser -S -H -D unbound
COPY --from=build /out/ /
ENTRYPOINT ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
