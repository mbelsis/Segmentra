FROM node:20-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY packages/compiler/package.json packages/compiler/
COPY packages/executor/package.json packages/executor/
COPY packages/db/package.json packages/db/
RUN npm ci --no-audit --no-fund --workspace web

COPY apps/web apps/web

# The browser calls the API with the relative base path /api; nginx (nginx.conf)
# proxies /api/ to the segmentra-app container, so no absolute API URL is baked in.
ENV VITE_API_URL=/api
RUN npm run build -w web

FROM nginx:alpine

COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
COPY infra/web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
