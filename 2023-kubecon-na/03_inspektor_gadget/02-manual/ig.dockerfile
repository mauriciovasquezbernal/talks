FROM ebpf-builder:latest as builder

ENV IG_EXPERIMENTAL=true

# ig binary (TODO: why is not the binary already there?)
COPY ig /bin/ig

# src for the gadget
COPY dns /tmp/dns
RUN ig image build /tmp/dns -t dns --local

COPY syscalls /tmp/syscalls
RUN ig image build /tmp/syscalls -t syscalls --local

FROM ubuntu
ENV IG_EXPERIMENTAL=true
ENV HOST_ROOT=/host

# ig binary
COPY ig /bin/ig
COPY --from=builder /var/lib/ig/oci-store /var/lib/ig/oci-store
