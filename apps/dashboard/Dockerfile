FROM oven/bun:1.3.9-alpine AS builder

WORKDIR /app

# Copy all workspace package.json files so bun can resolve the
# monorepo before installing. Listed in package.json's "workspaces":
# ["packages/*", "apps/*"] — every dir with a package.json must be
# present or `bun install --frozen-lockfile` fails.
COPY package.json bun.lock ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
COPY apps/docs/package.json ./apps/docs/package.json
COPY packages/auth/package.json ./packages/auth/package.json
COPY packages/codewire-design/package.json ./packages/codewire-design/package.json
COPY packages/codewire-proto-ts/package.json ./packages/codewire-proto-ts/package.json

RUN bun install --frozen-lockfile --ignore-scripts

COPY apps/dashboard ./apps/dashboard
COPY apps/docs ./apps/docs
COPY packages/codewire-design ./packages/codewire-design
COPY packages/codewire-proto-ts ./packages/codewire-proto-ts

WORKDIR /app/apps/dashboard
RUN bun run build
RUN cd /app/apps/docs && bun run build

FROM nginx:1.29-alpine

COPY apps/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/dashboard/dist /usr/share/nginx/html
COPY --from=builder /app/apps/docs/dist /usr/share/nginx/html/docs

EXPOSE 80
