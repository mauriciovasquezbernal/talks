FROM ghcr.io/inspektor-gadget/ig:latest as builder

FROM ubuntu

COPY --from=builder /usr/bin/ig /bin/ig
