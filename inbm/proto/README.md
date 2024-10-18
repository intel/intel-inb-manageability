# How to Generate Protobuf Files

1. Install grpc_tools (if not installed)

    ```sh
    python3 -m pip install --user grpcio-tools
    ```

2. Install (if not installed)

    ```sh
    pip3 install mypy-protobuf
    ```

3. Generate proto files

    ```sh
    cd /path/to/intel-inb-manageability/inbm
    ./generate-proto.sh
    ```
