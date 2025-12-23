export STORAGE_PATH="$PWD/data/recordings/grpc"
mkdir proto
cp -a $PWD/../backend/grpc-api-types/proto/. $PWD/proto
python -m grpc_tools.protoc \
    -I "$PWD/proto" \
    --python_out="$PWD/proto" \
    --grpc_python_out="$PWD/proto" \
    "$PWD/proto/"*.proto
cd frontend && npm run build && cd .. && rm -rf static && cp -r frontend/dist static
python -m uvicorn main:app --reload 