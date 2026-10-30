# Web 镜像：构建 React 产物并用 nginx 服务 + 反代 /api（架构设计 §2）

FROM node:22-alpine AS build
ARG NPM_REGISTRY=https://registry.npmjs.org/
WORKDIR /src
COPY package.json package-lock.json ./
# 慢网络下 npm 会因超时直接崩溃（"Exit handler never called"）：调大重试/超时、降低并发，
# 并用 BuildKit 缓存挂载保存已下载的 tarball，失败重跑时不必从零开始。
# 只用 npm ci：严格按 lockfile 安装，不回退到会改写依赖树的 npm install
RUN --mount=type=cache,target=/root/.npm \
    npm config set registry "$NPM_REGISTRY" \
 && npm config set fetch-retries 6 \
 && npm config set fetch-retry-mintimeout 20000 \
 && npm config set fetch-retry-maxtimeout 180000 \
 && npm config set fetch-timeout 600000 \
 && npm config set maxsockets 6 \
 && npm ci --no-audit --no-fund --prefer-offline
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 28765
