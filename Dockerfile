FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
RUN npm ci
COPY . .

FROM dependencies AS test
RUN npx playwright install --with-deps chromium
CMD ["npm", "run", "check"]

FROM dependencies AS build
RUN npm run build
# The dashboard is exported; its React/Next build dependencies are not runtime dependencies.
RUN npm prune --omit=dev --workspaces=false

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist/server ./dist/server
COPY --from=build --chown=node:node /app/apps/dashboard/out ./apps/dashboard/out
RUN mkdir .local && chown node:node .local
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 CMD ["node", "--input-type=module", "-e", "const r = await fetch('http://127.0.0.1:3000/api/health'); if (!r.ok) process.exit(1)"]
CMD ["node", "dist/server/server.js"]
