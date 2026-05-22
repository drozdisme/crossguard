from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from ..ir.graph import Handler, Param, Loc
from ..ir.types import Lattice
from ..analysis.selector import sn_keccak


class CaiParser:
    def __init__(self, d: dict, fname: str = "?"):
        self._d = d; self._f = fname

    @classmethod
    def load(cls, path: str):
        with open(path) as f: return cls(json.load(f), path)

    @classmethod
    def from_dict(cls, d: dict, fname="bridge.cairo"): return cls(d, fname)

    def parse(self) -> List[Handler]:
        abi = self._abi()
        out = [h for item in abi if item.get("type") == "l1_handler"
               for h in [self._handler(item)] if h]

        if not out:
            for ep in self._d.get("entry_points_by_type", {}).get("L1_HANDLER", []):
                raw = ep.get("selector", 0)
                sel = int(raw, 16) if isinstance(raw, str) else int(raw)
                out.append(Handler(self._name(), f"__h_{sel:#x}", Loc(self._f, 0), sel))
        return out

    def _handler(self, item: dict) -> Optional[Handler]:
        name = item.get("name", "").strip()
        if not name: return None
        params = [Param(i["name"], Lattice.cai(i["type"]), i["type"])
                  for i in item.get("inputs", []) if "name" in i]
        return Handler(
            contract=self._name(), fn=name,
            loc=Loc(self._f, item.get("__line", 0)),
            sel=sn_keccak(name), params=params,
            checked=self._taint(item, name),
        )

    def _taint(self, item: dict, fn: str) -> bool:
        ann = item.get("__crossguard_annotations") or {}
        if "has_from_address_check" in ann:
            return bool(ann["has_from_address_check"])
        body = (self._d.get("__source_map") or {}).get(fn, {}).get("body", "")
        if body: return "assert" in body and "from_address" in body
        return False

    def _abi(self) -> list:
        abi = self._d.get("abi", [])
        if isinstance(abi, str):
            try: abi = json.loads(abi)
            except: abi = []
        return abi if isinstance(abi, list) else []

    def _name(self) -> str:
        for i in self._abi():
            if i.get("type") == "impl":
                return i.get("name", "").removesuffix("Impl") or "?"
        return self._f.split("/")[-1].split(".")[0].replace("_", "").capitalize()
