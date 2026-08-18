FROM node:24-alpine AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/middleware-api/package.json apps/middleware-api/package.json
COPY apps/console/package.json apps/console/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY fixtures/ticketing/package.json fixtures/ticketing/package.json
RUN pnpm install --frozen-lockfile
COPY apps/middleware-api apps/middleware-api
COPY packages/contracts packages/contracts
COPY fixtures/ticketing fixtures/ticketing
RUN pnpm --filter @agentobe/middleware-api... build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
USER node
CMD ["node", "apps/middleware-api/dist/main.js"]
