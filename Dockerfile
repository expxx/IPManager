FROM node:20-bullseye-slim

WORKDIR /app
COPY . .
RUN npm install -g npm@latest \
    npm cache clear --force \
    && npm set progress=false \
    && npm config set registry http://registry.npmjs.org/ \
    && npm set audit false \
    && npm install --verbose \
    && npm install -g typescript ts-node

RUN tsc

FROM gcr.io/distroless/nodejs20-debian12
WORKDIR /app
COPY --from=0 /app /app

CMD ["dist/app.js"]