from typing import List, Dict, Any, Tuple, Optional
import re
import logging
from ..models.graph import SemanticDataFlowGraph, GraphNode, GraphEdge

logger = logging.getLogger(__name__)

class RouteResolver:
    """
    Resolves and links cross-stack routes (Frontend -> Backend).
    Matches API calls (fetch/axios) to Backend Route Handlers (Flask/Express).
    """
    
    def __init__(self, graph: SemanticDataFlowGraph):
        self.graph = graph

    def resolve_routes(self) -> int:
        """
        Finds network sinks and sources in the graph and creates linking edges.
        Returns number of links created.
        """
        sinks = self._find_network_sinks()
        sources = self._find_network_sources()
        
        logger.debug(f"RouteResolver: Found {len(sinks)} sinks and {len(sources)} sources")
        
        linked_count = 0
        for sink_node, url in sinks:
            for source_node, route in sources:
                if self._match_route(url, route):
                    logger.info(f"🔗 Linking Cross-Stack Flow: {url} -> {route}")
                    # Create edge
                    self.graph.add_edge(GraphEdge(
                        source_id=sink_node.id,
                        target_id=source_node.id,
                        type='network_flow',
                        label='HTTP Request',
                        metadata={'protocol': 'http', 'url': url, 'route': route}
                    ))
                    linked_count += 1
        
        return linked_count

    def _find_network_sinks(self) -> List[Tuple[GraphNode, str]]:
        """Find frontend API calls."""
        sinks = []
        for node in self.graph.nodes.values():
            if node.type == 'sink' and ('fetch' in node.label or 'axios' in node.label):
                url = node.metadata.get('url')
                if url:
                    sinks.append((node, url))
        return sinks

    def _find_network_sources(self) -> List[Tuple[GraphNode, str]]:
        """Find backend route handlers."""
        sources = []
        for node in self.graph.nodes.values():
            # Python/Flask sources
            if node.type == 'source' and 'request' in node.label:
                route = node.metadata.get('route')
                if route:
                    sources.append((node, route))
            # JS/Express sources (if any)
            elif node.metadata.get('route'):
                 sources.append((node, node.metadata.get('route')))
        return sources

    def _match_route(self, url: str, route: str) -> bool:
        """
        Match a concrete URL (from frontend) to a route pattern (from backend).
        Handles:
        - Exact match: /api/user == /api/user
        - Flask params: /api/user/123 matches /api/user/<id>
        - Express params: /api/user/123 matches /api/user/:id
        """
        # Normalize URL (strip domain)
        clean_url = url
        if '://' in clean_url:
            try:
                # Split http://domain.com/api/v1 -> /api/v1
                parts = clean_url.split('://', 1)[1].split('/', 1)
                clean_url = '/' + parts[1] if len(parts) > 1 else '/'
            except IndexError:
                clean_url = url

        # Exact match
        if clean_url == route:
            return True
            
        # Convert Flask/Express route pattern to Regex
        try:
            # Escape special chars
            pattern = re.escape(route)
            
            # Replace <param> (Flask) with regex [^/]+
            # pattern is escaped, so < becomes \<
            pattern = re.sub(r'\\<[^>]+\\>', r'[^/]+', pattern)
            
            # Replace :param (Express) with regex [^/]+
            pattern = re.sub(r'\\:[a-zA-Z0-9_]+', r'[^/]+', pattern)
            
            # Check match
            regex = f"^{pattern}$"
            return bool(re.match(regex, clean_url))
        except Exception:
            return False
