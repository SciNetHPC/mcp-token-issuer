FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run check && npm run build


FROM node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS production

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=5000
ENV HOME=/tmp

COPY package*.json ./
RUN npm ci --omit=dev

# The service only executes Node.  Drop every package manager and downloader
# from the production layer -- npm/corepack, the base image's Yarn, apk, and
# wget -- since no runtime path invokes them.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/bin/wget /sbin/apk \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app -h /tmp -s /sbin/nologin app

COPY --from=builder /app/dist ./dist

EXPOSE 5000

# The token store bind mount is owned by the same dedicated uid.  The image
# no longer carries tsx, npm, or the dev dependency tree.
USER 10001:10001

CMD ["node", "dist/index.js"]
