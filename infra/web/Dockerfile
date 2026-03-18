FROM node:20-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json /app/
COPY apps/web /app/apps/web
COPY packages/shared /app/packages/shared

RUN npm install --workspaces --include-workspace-root

# Set API URL to empty so the browser uses relative /api/ paths (proxied by nginx)
ENV VITE_API_URL=/api
RUN npm run build -w apps/web

FROM nginx:alpine

COPY --from=builder /app/apps/web/dist /usr/share/nginx/html
COPY infra/web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
