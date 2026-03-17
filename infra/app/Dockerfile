FROM node:20-bookworm-slim

WORKDIR /app

# Install docker.io for Ansible executor, openssh-client for SSH executor
RUN apt-get update && apt-get install -y --no-install-recommends docker.io openssh-client && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json /app/
COPY apps /app/apps
COPY packages /app/packages
COPY demo-data /app/demo-data

RUN npm install --workspaces --include-workspace-root
RUN npm run build -ws

EXPOSE 8080

CMD ["node", "apps/api/dist/index.js"]


