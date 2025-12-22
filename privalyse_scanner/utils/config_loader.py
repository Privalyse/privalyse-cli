import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any

# Use tomllib for Python 3.11+, fallback to tomli
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from ..models.config import ScanConfig, PolicyConfig

logger = logging.getLogger(__name__)

class ConfigLoader:
    """Loads configuration from privalyse.toml or pyproject.toml"""

    @staticmethod
    def load_config(root_path: Path) -> ScanConfig:
        """
        Load configuration from file, falling back to defaults.
        Priorities:
        1. privalyse.toml
        2. pyproject.toml [tool.privalyse]
        3. Defaults
        """
        config_data = {}
        
        # 1. Try privalyse.toml
        privalyse_toml = root_path / "privalyse.toml"
        if privalyse_toml.exists():
            try:
                with open(privalyse_toml, "rb") as f:
                    if tomllib:
                        data = tomllib.load(f)
                        config_data = data
                        logger.info(f"Loaded config from {privalyse_toml}")
            except Exception as e:
                logger.warning(f"Failed to parse {privalyse_toml}: {e}")

        # 2. Try pyproject.toml if no config found yet
        if not config_data:
            pyproject_toml = root_path / "pyproject.toml"
            if pyproject_toml.exists():
                try:
                    with open(pyproject_toml, "rb") as f:
                        if tomllib:
                            data = tomllib.load(f)
                            config_data = data.get("tool", {}).get("privalyse", {})
                            if config_data:
                                logger.info(f"Loaded config from {pyproject_toml}")
                except Exception as e:
                    logger.warning(f"Failed to parse {pyproject_toml}: {e}")

        return ConfigLoader._create_scan_config(config_data, root_path)

    @staticmethod
    def _create_scan_config(data: Dict[str, Any], root_path: Path) -> ScanConfig:
        """Convert dictionary to ScanConfig object"""
        
        # Extract Policy
        policy_data = data.get("policy", {})
        policy = PolicyConfig(
            blocked_countries=policy_data.get("blocked_countries", []),
            blocked_providers=policy_data.get("blocked_providers", []),
            allowed_countries=policy_data.get("allowed_countries", []),
            require_sanitization_for_ai=policy_data.get("require_sanitization_for_ai", False)
        )
        
        # Extract other config
        return ScanConfig(
            root_path=root_path,
            exclude_patterns=data.get("exclude", []) or ScanConfig().exclude_patterns,
            max_workers=data.get("max_workers", 8),
            verbose=data.get("verbose", False),
            debug=data.get("debug", False),
            policy=policy
        )
