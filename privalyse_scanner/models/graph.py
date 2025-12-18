"""
Semantic Data Flow Graph Model
Represents the flow of data through the application.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import json

@dataclass
class GraphNode:
    """Represents a node in the data flow graph"""
    id: str
    type: str  # 'variable', 'function', 'class', 'file', 'source', 'sink', 'transform'
    label: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "metadata": self.metadata
        }

@dataclass
class GraphEdge:
    """Represents a directed edge in the data flow graph"""
    source_id: str
    target_id: str
    type: str  # 'data_flow', 'call', 'contains', 'imports'
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.type,
            "label": self.label,
            "metadata": self.metadata
        }

class SemanticDataFlowGraph:
    """
    Global graph representing data flows across the entire codebase.
    """
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._node_ids: Set[str] = set()

    def add_node(self, node: GraphNode):
        if node.id not in self._node_ids:
            self.nodes[node.id] = node
            self._node_ids.add(node.id)

    def add_edge(self, edge: GraphEdge):
        # Ensure nodes exist (or create placeholders)
        if edge.source_id not in self._node_ids:
            self.add_node(GraphNode(id=edge.source_id, type="unknown", label=edge.source_id))
        if edge.target_id not in self._node_ids:
            self.add_node(GraphNode(id=edge.target_id, type="unknown", label=edge.target_id))
        
        self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }

    def to_dot(self) -> str:
        """Export to Graphviz DOT format for visualization"""
        lines = ["digraph DataFlow {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
        
        for node in self.nodes.values():
            color = "black"
            if node.type == 'source': color = "red"
            elif node.type == 'sink': color = "blue"
            elif node.type == 'variable': color = "gray"
            
            label = f"{node.label}\\n({node.type})"
            lines.append(f'  "{node.id}" [label="{label}", color="{color}"];')
            
        for edge in self.edges:
            style = "solid"
            if edge.type == 'call': style = "dashed"
            label = f' [label="{edge.label}"]' if edge.label else ""
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [style="{style}"];')
            
        lines.append("}")
        return "\n".join(lines)
