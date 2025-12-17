# Contributing to Privalyse

Thank you for considering contributing to Privalyse! 🎉

## How to Contribute

### Reporting Issues
- Use GitHub Issues to report bugs or request features
- Include Python version, OS, and minimal reproduction steps
- Check existing issues first to avoid duplicates

### Submitting Changes

1. **Fork & Clone**
```bash
git clone https://github.com/privalyse/privalyse-cli.git
cd privalyse-cli
```

2. **Create Branch**
```bash
git checkout -b feature/your-feature-name
```

3. **Setup Development Environment**
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e .
```

4. **Make Changes**
- Follow PEP 8 style guide
- Add tests if applicable
- Update documentation if needed

5. **Test Your Changes**
```bash
# Run on example apps
python3 -m privalyse_scanner.cli --root examples/bad-practice-app --out test_scan.md

# If you added tests
python3 -m unittest discover tests
```

6. **Commit & Push**
```bash
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature-name
```

7. **Open Pull Request**
- Describe what changed and why
- Reference related issues
- Wait for review

## Development Guidelines

### Code Style
- Use Python 3.8+ features
- Type hints are appreciated but not required
- Keep functions focused (single responsibility)
- Add docstrings for public functions

### Commit Messages
Follow conventional commits:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `refactor:` - Code restructuring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

### Adding Language Support

To add a new language analyzer:

1. Create `privalyse_scanner/analyzers/{language}_analyzer.py`
2. Inherit from `BaseAnalyzer`
3. Implement `analyze_file()` method
4. Register in `privalyse_scanner/core/scanner.py`

Example:
```python
from privalyse_scanner.analyzers.base_analyzer import BaseAnalyzer

class GoAnalyzer(BaseAnalyzer):
    def analyze_file(self, file_path: str) -> List[Finding]:
        # Your implementation
        pass
```

### Adding Detection Rules

PII patterns are in `privalyse_scanner/analyzers/{language}_analyzer.py`:

```python
# Add to SECRET_PATTERNS dict
'new_secret': r'(pattern|regex|here)'
```

## Testing

### Manual Testing
```bash
# Test on real codebases
python privalyse_v2.py --root /path/to/real/project --out test.md

# Test output formats
python privalyse_v2.py --root examples/vulnerable-app --format json --out test.json
```

### What to Test
- [ ] Scanner runs without errors
- [ ] Findings are accurate (no false positives)
- [ ] Output format is correct (Markdown/JSON)
- [ ] Works on different Python versions (3.8+)
- [ ] Examples still scan correctly

## Community

- **Questions?** Open a GitHub Discussion
- **Security Issue?** Email security@privalyse.com (don't use public issues)
- **Feature Request?** Open an issue with [Feature] tag

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making Privalyse better!** 🚀
