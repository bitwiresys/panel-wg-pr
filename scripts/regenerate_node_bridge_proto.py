import importlib
import shutil
import sys
import tempfile
from pathlib import Path

from grpc_tools import protoc
from PasarGuardNodeBridge.common import service_pb2

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "proto" / "service.proto"
BRIDGE_PROTO_DIR = Path(service_pb2.__file__).resolve().parent
BRIDGE_PACKAGE_PARTS = BRIDGE_PROTO_DIR.relative_to(BRIDGE_PROTO_DIR.parents[1]).parts
BULK_RPC = "GetUsersOnlineIpListStats"


def _regenerate_messages() -> None:
    result = protoc.main(
        [
            "grpc_tools.protoc",
            f"-I{PROTO.parent}",
            f"--python_out={BRIDGE_PROTO_DIR}",
            str(PROTO),
        ]
    )
    if result:
        raise SystemExit(result)


def _find_grpclib_plugin() -> str:
    venv_bin = Path(sys.executable).parent
    candidate = venv_bin / "protoc-gen-grpclib_python"
    if candidate.exists():
        return str(candidate)

    plugin = shutil.which("protoc-gen-grpclib_python")
    if plugin:
        return plugin

    raise SystemExit("protoc-gen-grpclib_python not found (pip install grpclib)")


def _regenerate_grpclib_stub() -> None:
    plugin = _find_grpclib_plugin()

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        staged_dir = tmp.joinpath(*BRIDGE_PACKAGE_PARTS)
        staged_dir.mkdir(parents=True)
        staged_proto = staged_dir / PROTO.name
        staged_proto.write_bytes(PROTO.read_bytes())

        result = protoc.main(
            [
                "grpc_tools.protoc",
                f"-I{tmp}",
                f"--plugin=protoc-gen-grpclib_python={plugin}",
                f"--grpclib_python_out={tmp}",
                str(staged_proto),
            ]
        )
        if result:
            raise SystemExit(result)

        generated = staged_dir / "service_grpc.py"
        shutil.copyfile(generated, BRIDGE_PROTO_DIR / "service_grpc.py")


def _verify_bulk_rpc() -> None:
    stub_source = (BRIDGE_PROTO_DIR / "service_grpc.py").read_text(encoding="utf-8")
    if f"self.{BULK_RPC} = grpclib.client.UnaryUnaryMethod(" not in stub_source:
        raise SystemExit(f"{BULK_RPC} missing from generated grpclib stub")
    if f"/service.NodeService/{BULK_RPC}" not in stub_source:
        raise SystemExit(f"{BULK_RPC} route missing from generated grpclib stub")


def main() -> None:
    _regenerate_messages()
    _regenerate_grpclib_stub()
    _verify_bulk_rpc()

    importlib.invalidate_caches()


if __name__ == "__main__":
    main()
