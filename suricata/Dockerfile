# 引擎镜像：Suricata 7.x + engine-agent（unix-socket 模式，见架构设计 §3.1/§3.2）
FROM golang:1.25-alpine AS agentbuild
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/engine-agent ./cmd/engine-agent

FROM jasonish/suricata:7.0
COPY --from=agentbuild /out/engine-agent /usr/local/bin/engine-agent
COPY suricata/suricata.yaml /etc/suricata/suricata.yaml
COPY suricata/entrypoint.sh /entrypoint.sh
COPY rules/spycam.rules /etc/suricata/rules/spycam.rules
RUN chmod +x /entrypoint.sh && mkdir -p /etc/suricata/rules-active
ENTRYPOINT ["/entrypoint.sh"]
