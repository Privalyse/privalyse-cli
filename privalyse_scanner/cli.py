#!/usr/bin/env python3
"""
Privalyse Scanner - Privacy & GDPR Compliance Scanner

Turn your codebase into a GDPR compliance report in seconds.
Zero config, instant insights.
"""

import sys
import json
import argparse
import logging
from pathlib import Path

# Try to import rich, fail gracefully if not installed
try:
    from privalyse_scanner.utils import ui
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from privalyse_scanner import PrivalyseScanner
from privalyse_scanner.models.config import ScanConfig
from privalyse_scanner.models.finding import Finding, ClassificationResult
from privalyse_scanner.exporters import MarkdownExporter, HTMLExporter
from privalyse_scanner.utils.visualizer import FlowVisualizer


class PrivalyseJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for Privalyse objects"""
    def default(self, obj):
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


def setup_logging(debug: bool = False, quiet: bool = False):
    """Configure logging"""
    if quiet:
        level = logging.ERROR
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S',
        level=level
    )


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Privalyse Scanner v0.1 - Privacy & GDPR Compliance Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan current directory
  privalyse
  
  # Scan specific directory with output
  privalyse --root ./backend/src --out results.json
  
  # Verbose output
  privalyse --root ./backend --verbose
  
  # Debug mode
  privalyse --root ./backend --debug
        """
    )
    
    # Paths
    parser.add_argument('--root', type=Path, default=Path.cwd(),
                       help='Root directory to scan (default: current directory)')
    parser.add_argument('--out', type=str, default='scan_results.md',
                       help='Output file path (default: scan_results.md)')
    parser.add_argument('--exclude', action='append',
                       help='Glob patterns to exclude (can be used multiple times)')
    
    # Performance
    parser.add_argument('--max-workers', type=int, default=8,
                       help='Maximum parallel workers (default: 8)')
    parser.add_argument('--max-files', type=int,
                       help='Maximum files to scan (for testing)')
    
    # Output
    parser.add_argument('--format', type=str, default='md',
                       choices=['json', 'markdown', 'md', 'html'],
                       help='Output format (default: md)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--quiet', action='store_true',
                       help='Quiet mode (errors only)')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    
    # Commands
    parser.add_argument('--init', action='store_true',
                       help='Initialize .privalyseignore file')
    
    args = parser.parse_args()
    
    # Handle init command
    if args.init:
        ignore_path = Path.cwd() / '.privalyseignore'
        if ignore_path.exists():
            if HAS_RICH:
                ui.print_warning(f"{ignore_path} already exists.")
            else:
                print(f"⚠️  {ignore_path} already exists.")
            sys.exit(0)
        
        with open(ignore_path, 'w') as f:
            f.write("# Privalyse Ignore File\n")
            f.write("# Add patterns to ignore files or specific rules\n")
            f.write("# Format: rule_id:file_pattern or just file_pattern\n\n")
            f.write("# Ignore test files\n")
            f.write("tests/*\n")
            f.write("*_test.py\n")
            f.write("*.test.js\n\n")
            f.write("# Ignore specific rules in specific files\n")
            f.write("# HARDCODED_SECRET:config/dev_settings.py\n")
        
        if HAS_RICH:
            ui.print_success(f"Created {ignore_path}")
        else:
            print(f"✅ Created {ignore_path}")
        sys.exit(0)
    
    # Setup logging
    setup_logging(debug=args.debug, quiet=args.quiet)
    logger = logging.getLogger(__name__)
    
    # Rich Banner
    if HAS_RICH:
        ui.print_banner()
    else:
        logger.info("🔍 Privalyse Scanner v0.1 (Modular)")
    
    # Create config
    config = ScanConfig(
        root_path=args.root,
        max_workers=args.max_workers,
        max_files=args.max_files,
        verbose=args.verbose,
        debug=args.debug,
    )
    
    # Load .privalyseignore if it exists and add file patterns to config
    ignore_file = config.root_path / '.privalyseignore'
    if ignore_file.exists():
        try:
            with open(ignore_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Only add file patterns (no colons) to exclude_patterns
                        # Rule-specific ignores (with colons) are handled by the scanner
                        if ':' not in line:
                            config.exclude_patterns.append(line)
            if args.verbose:
                logger.info(f"ℹ️  Loaded ignore patterns from {ignore_file}")
        except Exception as e:
            logger.warning(f"⚠️  Failed to read .privalyseignore: {e}")
    
    # Add user excludes if provided
    if args.exclude:
        config.exclude_patterns.extend(args.exclude)
    
    # Create and run scanner
    if HAS_RICH and not args.debug and not args.verbose:
        with ui.create_progress() as progress:
            task = progress.add_task("Scanning codebase...", total=None)
            scanner = PrivalyseScanner(config)
            results = scanner.scan()
            progress.update(task, completed=100)
    else:
        logger.info(f"📁 Scanning: {config.root_path}")
        scanner = PrivalyseScanner(config)
        results = scanner.scan()
    
    # Write results in requested format
    output_path = Path(args.out)
    
    # Auto-detect format from extension if not explicitly specified
    output_format = args.format
    if output_format == 'json' and args.out != 'scan_results.json':
        # If user changed output path but kept default format, try to infer
        if str(output_path).endswith(('.md', '.markdown')):
            output_format = 'markdown'
        elif str(output_path).endswith('.html'):
            output_format = 'html'
    
    if output_format in ['markdown', 'md']:
        # Generate markdown report
        exporter = MarkdownExporter()
        markdown_report = exporter.export(results)
        
        # Ensure .md extension
        if not str(output_path).endswith('.md'):
            output_path = output_path.with_suffix('.md')
        
        with output_path.open('w', encoding='utf-8') as f:
            f.write(markdown_report)
    
    elif output_format == 'html':
        # Generate HTML report
        exporter = HTMLExporter()
        
        # Ensure .html extension
        if not str(output_path).endswith('.html'):
            output_path = output_path.with_suffix('.html')
        
        exporter.export(results, output_path)
    
    else:
        # Default JSON output
        # Fix for sets in dependency_graph (JSON serialization support)
        if 'dependency_graph' in results:
            for k, v in results['dependency_graph'].items():
                if isinstance(v, set):
                    results['dependency_graph'][k] = list(v)

        with output_path.open('w') as f:
            json.dump(results, f, indent=2, cls=PrivalyseJSONEncoder)
    
    # Print summary
    compliance = results['compliance']
    findings_data = results['findings']
    
    # Convert dict findings back to objects for UI if needed
    findings_objects = []
    for f in findings_data:
        # Reconstruct ClassificationResult
        class_data = f.get('classification', {})
        classification = ClassificationResult(
            pii_types=class_data.get('pii_types', []),
            sectors=class_data.get('sectors', []),
            severity=class_data.get('severity', 'info'),
            article=class_data.get('article'),
            legal_basis_required=class_data.get('legal_basis_required', False),
            category=class_data.get('category', 'unknown'),
            confidence=class_data.get('confidence', 0.0),
            reasoning=class_data.get('reasoning', ''),
            gdpr_articles=class_data.get('gdpr_articles', [])
        )

        finding_obj = Finding(
            rule=f.get('rule', 'UNKNOWN'),
            severity=f.get('severity', 'info'),
            file=f.get('file', ''),
            line=f.get('line', 0),
            snippet=f.get('snippet', ''),
            classification=classification,
            flow_path=f.get('flow_path', [])
        )
        findings_objects.append(finding_obj)

    if HAS_RICH:
        ui.print_findings_summary(findings_objects, compliance)
        ui.print_success(f"Report generated: {output_path}")
        
        # Visual Summary of Top Risks
        ui.console.print("\n[bold]🔍 Top Data Flow Risks:[/bold]")
        
        # Filter for high/critical with flow paths
        risky_flows = [f for f in findings_objects if f.severity in ['critical', 'high'] and f.flow_path]
        
        for i, finding in enumerate(risky_flows[:3]): # Show top 3
            ui.print_flow_tree(finding, None)
            
        if len(risky_flows) > 3:
            ui.console.print(f"[italic]... and {len(risky_flows) - 3} more flow risks in the report.[/italic]")
            
    else:
        # Fallback to old output
        findings_count = results['meta']['total_findings']
        score = compliance['score']
        
        if score >= 90:
            emoji = "🟢"
        elif score >= 70:
            emoji = "🟡"
        else:
            emoji = "🔴"
        
        print(f"\n{emoji} Compliance Score: {score}/100 ({compliance['status']})")
        print(f"📊 Findings: {findings_count} total")
        if compliance.get('critical_findings'):
            print(f"🔴 Critical: {compliance['critical_findings']}")
        if compliance.get('high_findings'):
            print(f"🟠 High: {compliance['high_findings']}")
        print(f"📄 Report: {output_path}")
        
        # Visual Summary
        FlowVisualizer.print_summary(results)
        
        logger.info("✅ Scan complete")
    
    return 0 if compliance['score'] >= 70 else 1


def cli():
    """CLI entry point for PyPI package"""
    sys.exit(main())


if __name__ == "__main__":
    cli()
