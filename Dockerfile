# SealDrop: one image with the Go server and the built web client.
# Stage 1: Rust core -> WebAssembly
FROM rust:1-bookworm AS wasm
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-pack --version 0.15.0 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY wasm ./wasm
COPY cli ./cli
RUN cd wasm && wasm-pack build --release --target web --out-dir /src/web/src/pkg

# Stage 2: TypeScript client -> static files
FROM node:22-bookworm-slim AS web
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
COPY --from=wasm /src/web/src/pkg ./src/pkg
RUN npm run build

# Stage 3: Go server (pure Go SQLite, no cgo)
FROM golang:1.27-bookworm AS server
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sealdrop-server .

# Runtime: small, non-root
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=server /sealdrop-server /app/sealdrop-server
COPY --from=web /src/web/dist /app/web
ENV SEALDROP_STATIC=/app/web SEALDROP_DB=/tmp/sealdrop/sealdrop.db
EXPOSE 8080
ENTRYPOINT ["/app/sealdrop-server"]
