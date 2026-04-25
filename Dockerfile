# ---- Build WASM ----
FROM rust:1.95-slim AS builder
WORKDIR /app
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-pack
COPY . .
RUN cd wasm && wasm-pack build --target web
RUN cp -r wasm/pkg/* .

FROM nginx:alpine
WORKDIR /srv
COPY --from=builder /app/wasm/index.html /srv/
COPY --from=builder /app/wasm/src /srv/src
COPY --from=builder /app/wasm/pkg /srv/pkg
COPY /wasm/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
