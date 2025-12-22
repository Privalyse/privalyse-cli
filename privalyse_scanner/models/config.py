"""Scanner configuration models"""

from dataclasses import dataclass, field
from typing import List, Optional, Set
from pathlib import Path


@dataclass
class PolicyConfig:
    """User-defined privacy policy configuration"""
    blocked_countries: List[str] = field(default_factory=list)
    blocked_providers: List[str] = field(default_factory=list)
    allowed_countries: List[str] = field(default_factory=list)
    require_sanitization_for_ai: bool = False
    
    def is_country_allowed(self, country_code: str) -> bool:
        """Check if country is allowed based on policy"""
        if not country_code:
            return True
            
        # Normalize
        country_code = country_code.upper()
        
        # Block list takes precedence
        for blocked in self.blocked_countries:
            if blocked.upper() in country_code:
                return False
                
        # Allow list (if defined, everything else is blocked)
        if self.allowed_countries:
            for allowed in self.allowed_countries:
                if allowed.upper() in country_code:
                    return True
            return False
            
        return True

    def is_provider_allowed(self, provider: str) -> bool:
        """Check if provider is allowed"""
        if not provider:
            return True
            
        for blocked in self.blocked_providers:
            if blocked.lower() in provider.lower():
                return False
        return True


@dataclass
class ScanConfig:
    """Configuration for scanner execution"""
    
    # Paths and filters
    root_path: Path = field(default_factory=lambda: Path.cwd())
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*/node_modules/*", "*/venv/*", "*/env/*", "*/.venv/*", "*/dist/*",
        "*/build/*", "*/__pycache__/*", "*/.git/*", "*/site-packages/*",
        "*/demo_stage/*", "*/tests/*", "*/scan_results.json"
    ])
    
    # Policy
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    
    # Performance
    max_workers: int = 8
    max_files: Optional[int] = None
    max_file_size: int = 5_000_000  # 5MB default
    
    # Output
    verbose: bool = False
    debug: bool = False
    
    # Language support
    python_extensions: Set[str] = field(default_factory=lambda: {'.py', '.pyw'})
    js_extensions: Set[str] = field(default_factory=lambda: {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})
    config_extensions: Set[str] = field(default_factory=lambda: {'.json', '.yaml', '.yml', '.toml', '.ini', '.env'})
    docker_files: Set[str] = field(default_factory=lambda: {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'})
    
    def __post_init__(self):
        """Convert paths to Path objects"""
        if not isinstance(self.root_path, Path):
            self.root_path = Path(self.root_path)
