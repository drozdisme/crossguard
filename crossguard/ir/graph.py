from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
from .types import T


@dataclass
class Loc:
    file: str; line: int; col: int = 0
    def __str__(self): return f"{self.file}:{self.line}:{self.col}"


@dataclass
class Send:
    contract: str; fn: str; loc: Loc
    to: str; sel_val: Optional[int]; sel_expr: str
    payload: List[T] = field(default_factory=list)
    has_fee: bool = False


@dataclass
class Param:
    name: str; typ: T; raw: str


@dataclass
class Handler:
    contract: str; fn: str; loc: Loc; sel: int
    params: List[Param] = field(default_factory=list)
    checked: bool = False


@dataclass
class Edge:
    send: Send; handler: Handler; sel: int; how: str = "exact"


@dataclass
class Graph:
    sends: List[Send]    = field(default_factory=list)
    handlers: List[Handler] = field(default_factory=list)
    edges: List[Edge]    = field(default_factory=list)

    def add_send(self, s): self.sends.append(s)
    def add_handler(self, h): self.handlers.append(h)
    def add_edge(self, e): self.edges.append(e)
