FROM --platform=$BUILDPLATFORM golang:1.26.0@sha256:9edf71320ef8a791c4c33ec79f90496d641f306a91fb112d3d060d5c1cee4e20 AS builder

WORKDIR /builder

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy the go source
COPY main.go .
COPY pkg pkg

ARG TARGETOS
ARG TARGETARCH
# COMPAT-7: Explicitly name the output binary kubelogin-daemon (not the module's
# default name) to avoid confusion with upstream kubelogin.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o kubelogin-daemon

FROM gcr.io/distroless/base-debian12
COPY --from=builder /builder/kubelogin-daemon /
# COMPAT-MED-2: Run as non-root. UID 65532 is the "nonroot" user in distroless images.
USER 65532:65532
ENTRYPOINT ["/kubelogin-daemon"]
