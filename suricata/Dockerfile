# 引擎镜像：Suricata 7.x + engine-agent（unix-socket 模式，见架构设计 §3.1/§3.2）
FROM golang:1.25-alpine AS agentbuild
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/engine-agent ./cmd/engine-agent

FROM jasonish/suricata:7.0
COPY --from=agentbuild /out/engine-agent /usr/local/bin/engine-agent
# 配置与规则放 /opt/spycam：基础镜像声明了 VOLUME /etc/suricata，compose 重建容器会沿用旧匿名卷，放那里的文件更新永远不生效
COPY suricata/suricata.yaml /opt/spycam/suricata.yaml
COPY suricata/entrypoint.sh /entrypoint.sh
COPY suricata/entrypoint-live.sh /entrypoint-live.sh
COPY suricata/rules-path.sh /usr/local/lib/spycam/rules-path.sh
COPY rules/spycam.rules /opt/spycam/rules/spycam.rules
RUN chmod +x /entrypoint.sh /entrypoint-live.sh && mkdir -p /opt/spycam/rules-active
ENTRYPOINT ["/entrypoint.sh"]
