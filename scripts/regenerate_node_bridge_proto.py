"""Regenerate the installed node bridge protobufs (messages + gRPC stubs) from
the panel contract.

Why both: the published pasarguard-node-bridge wheel lags the panel's contract
in two ways -- missing message fields (e.g. WireGuard.pre_shared_key) and,
for RPCs added since the last bridge release (e.g. GetUsersOnlineIpListStats),
missing the grpclib client stub entirely. Regenerating service_pb2.py alone
(grpc_tools.protoc) only fixes the former; the grpclib stub (service_grpc.py)
needs the grpclib package's own protoc plugin.

TODO(bridge): once pasarguard-node-bridge publishes GetUsersOnlineIpListStats,
this script's grpclib-stub regeneration (and the direct-stub call in
app/operation/node.py's _get_node_users_ip_list_bulk_safe) can both be removed.
"""

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
# Package path the installed wheel expects generated imports to use, e.g.
# `import PasarGuardNodeBridge.common.service_pb2` inside service_grpc.py.
BRIDGE_PACKAGE_PARTS = BRIDGE_PROTO_DIR.relative_to(BRIDGE_PROTO_DIR.parents[1]).parts


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
    # The console script lives next to the interpreter running this script
    # (venv/bin), which isn't necessarily on PATH during a build step. Do not
    # resolve() sys.executable: venv pythons are often symlinks to a system
    # interpreter, and following the symlink would land outside venv/bin.
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
        # protoc derives the generated `import x.y.service_pb2` statement from
        # the proto's path relative to -I, so mirror the installed package
        # layout here rather than regenerating in place.
        staged_dir = tmp.joinpath(*BRIDGE_PACKAGE_PARTS)
        staged_dir.mkdir(parents=True)
        staged_proto = staged_dir / PROTO.name
        staged_proto.write_bytes(PROTO.read_bytes())

        # Use grpc_tools' bundled protoc binary (like _regenerate_messages) so
        # this doesn't depend on a system-installed `protoc` on the image.
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


def main() -> None:
    _regenerate_messages()
    _regenerate_grpclib_stub()

    importlib.invalidate_caches()


if __name__ == "__main__":
    main()
