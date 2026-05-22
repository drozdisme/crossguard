from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class K(Enum):
    UINT = "uint"; INT = "int"; ADDR = "address"; BOOL = "bool"
    FELT = "felt252"; BYTES = "bytes"; B32 = "bytes32"
    ARR = "array"; STRUCT = "struct"; UNK = "unknown"


@dataclass(frozen=True)
class T:
    kind: K
    bits: Optional[int] = None
    inner: Optional[T] = None
    name: Optional[str] = None

    def slots(self) -> int:
        if self.kind == K.UINT and self.bits == 256: return 2
        if self.kind in (K.UINT, K.INT, K.ADDR, K.BOOL, K.FELT, K.B32): return 1
        if self.kind in (K.ARR, K.BYTES, K.STRUCT): return -1
        return 1

    def is_u256(self) -> bool:
        return self.kind == K.UINT and self.bits == 256

    def __repr__(self):
        if self.kind == K.UINT:  return f"UInt({self.bits})"
        if self.kind == K.INT:   return f"Int({self.bits})"
        if self.kind == K.ARR:   return f"Array<{self.inner!r}>"
        if self.kind == K.STRUCT: return f"Struct({self.name})"
        if self.kind == K.UNK:  return f"?({self.name})"
        return self.kind.value


U256 = T(K.UINT, 256); U128 = T(K.UINT, 128); U64 = T(K.UINT, 64)
U32 = T(K.UINT, 32);   U16 = T(K.UINT, 16);   U8 = T(K.UINT, 8)
ADDR = T(K.ADDR); BOOL = T(K.BOOL); FELT = T(K.FELT); B32 = T(K.B32)


class Lattice:
    _SOL = {
        "uint256": U256, "uint128": U128, "uint64": U64, "uint32": U32,
        "uint16": U16, "uint8": U8, "uint": U256,
        "int256": T(K.INT, 256), "int128": T(K.INT, 128), "int": T(K.INT, 256),
        "address": ADDR, "bool": BOOL, "bytes32": B32, "bytes": T(K.BYTES), "string": T(K.BYTES),
    }
    _CAI = {
        "u256": U256, "u128": U128, "u64": U64, "u32": U32, "u16": U16, "u8": U8,
        "felt252": FELT, "ContractAddress": ADDR, "EthAddress": ADDR, "bool": BOOL,
        "core::integer::u256": U256, "core::integer::u128": U128,
        "core::integer::u64": U64,   "core::integer::u32": U32,
        "core::felt252": FELT,
        "core::starknet::contract_address::ContractAddress": ADDR,
        "core::starknet::eth_address::EthAddress": ADDR,
        "core::bool": BOOL,
    }

    @classmethod
    def sol(cls, s: str) -> T:
        s = s.strip()
        if s.endswith("[]"): return T(K.ARR, inner=cls.sol(s[:-2]))
        if s.endswith("]"):  return T(K.ARR, inner=cls.sol(s[:s.rfind("[")]))
        if s.startswith("uint") and s[4:].isdigit(): return T(K.UINT, int(s[4:]))
        if s.startswith("int")  and s[3:].isdigit(): return T(K.INT,  int(s[3:]))
        return cls._SOL.get(s, T(K.UNK, name=s))

    @classmethod
    def cai(cls, s: str) -> T:
        s = s.strip()
        return cls._CAI.get(s) or cls._CAI.get(s.split("::")[-1]) or T(K.UNK, name=s)
