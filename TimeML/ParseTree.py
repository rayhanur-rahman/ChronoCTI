from typing import List


class Node:
    def __init__(self) -> None:
        self.pos : str | None = None
        self.word : str | None = None
        self.children : List[Node] = []
        self.Parent : Node | None = None
        self.index : int = -1