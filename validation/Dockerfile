# syntax=docker/dockerfile:1
# Validator 镜像：数据自验工具（P2 阶段填充完整评测逻辑）
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY run_validation.py ./
ENTRYPOINT ["python", "run_validation.py"]
