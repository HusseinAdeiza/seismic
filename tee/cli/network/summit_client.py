import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

GenesisText = str
Json = Any


@dataclass
class PublicKeys:
    node: str
    consensus: str


class SummitClient:
    """Client for a node's summit RPC.

    Summit's RPC is jsonrpsee (JSON-RPC 2.0): a single POST endpoint, method
    names in camelCase (see summit/rpc/src/api.rs). nginx proxies `/summit` →
    localhost:3030 and strips the prefix, so we POST the envelope to the
    `/summit` base — there is no per-method REST path or GET.
    """

    def __init__(self, url: str):
        self.url = url

    def _rpc(self, method: str, params: list | None = None) -> Json:
        response = requests.post(
            self.url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"summit RPC {method} failed: {data['error']}")
        return data["result"]

    def health(self) -> str:
        return self._rpc("health")

    def get_public_keys(self) -> PublicKeys:
        keys = self._rpc("getPublicKeys")
        return PublicKeys(node=keys["node"], consensus=keys["consensus"])

    def send_genesis(self, genesis: GenesisText) -> str:
        self.validate_genesis_text(genesis)
        return self._rpc("sendGenesis", [genesis])

    def post_genesis_filepath(self, path: Path):
        self.send_genesis(self.load_genesis_file(path))

    @staticmethod
    def load_genesis_file(path: Path) -> GenesisText:
        with open(path) as f:
            return f.read()

    @staticmethod
    def validate_genesis_text(genesis: GenesisText) -> dict[str, Any]:
        try:
            return tomllib.loads(genesis)
        except tomllib.TOMLDecodeError as e:
            logger.error(
                "\n".join(
                    [
                        f"Failed to parse genesis as toml: {e}",
                        "File contents:",
                        genesis,
                    ]
                )
            )
            raise e

    @classmethod
    def load_genesis_toml(cls, path: Path) -> dict[str, Any]:
        text = cls.load_genesis_file(path)
        return cls.validate_genesis_text(text)
