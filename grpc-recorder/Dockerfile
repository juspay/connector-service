FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies (minimal for file-based storage)
RUN pip install --no-cache-dir xds-protos grpcio grpcio-tools fastapi uvicorn deepdiff

# Copy the recorder service
COPY ./grpc-recorder .
COPY ./backend/grpc-api-types/proto /protos

RUN python -m grpc_tools.protoc \
    -I /protos \
    --python_out=/app \
    --grpc_python_out=/app \
    /protos/*.proto

# Create data directory for file storage
RUN mkdir -p /data/recordings && chmod 777 /data/recordings

EXPOSE 50051
# Expose HTTP port
EXPOSE 8000

# Environment variables
ENV GRPC_PORT=50051
ENV STORAGE_PATH=/data/recordings
ENV HTTP_PORT=8000
ENV GRPC_TARGET=connector-grpc-server:8085

ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python 

# Build frontend code
WORKDIR /app/frontend
RUN npm install
RUN npm run build
WORKDIR /app
RUN rm -rf static && cp -r frontend/dist static

# Run the service
CMD ["python", "main.py"]