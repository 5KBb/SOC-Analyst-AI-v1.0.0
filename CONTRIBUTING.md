# Contributing to SOC Analyst AI

Thank you for your interest in contributing to SOC Analyst AI! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Log file examples (if applicable)
- Your environment (OS, Python version)

### Suggesting Features

Feature requests are welcome! Please open an issue describing:
- The feature and why it would be useful
- Use cases
- Possible implementation approach

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Test thoroughly**: Ensure all existing tests pass
5. **Add tests** for new functionality
6. **Update documentation** if needed
7. **Commit with clear messages**: `git commit -m "Add: new firewall parser for XYZ"`
8. **Push to your fork**: `git push origin feature/your-feature-name`
9. **Open a Pull Request**

### Code Style

- Follow PEP 8 Python style guide
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and small
- Write clear, self-documenting code

### Testing

- Test your changes with real log files
- Ensure PDF generation works correctly
- Verify parser auto-detection
- Check that MITRE mapping is accurate

### Adding New Parsers

To add support for a new log source:

1. Create new parser in `src/parsers/`
2. Inherit from `BaseParser`
3. Implement `parse_line()` method
4. Add detection patterns for suspicious activity
5. Update `soc_cli.py` auto-detection
6. Add sample log file to `data/samples/`
7. Update documentation

Example:
```python
from .base_parser import BaseParser, ParsedEvent

class MyNewParser(BaseParser):
    def __init__(self):
        super().__init__(source_type="mynewtype")
    
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        # Your parsing logic here
        pass
```

### Adding MITRE Techniques

To add new MITRE ATT&CK mappings:

1. Edit `src/mitre/mitre_mapper.py`
2. Add technique to `_load_techniques_database()`
3. Add detection logic in `_identify_techniques()`
4. Test with relevant log samples

### Documentation

- Update README.md if adding major features
- Add examples to QUICKSTART.md
- Update configuration docs for new settings
- Keep Italian guide (GUIDA_ITALIANA.md) in sync

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/soc-analyst-ai.git
cd soc-analyst-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in development mode
pip install -e .
pip install -r requirements.txt

# Run tests
pytest
```

## Commit Message Guidelines

Use clear, descriptive commit messages:

- `Add: new feature X`
- `Fix: bug in parser Y`
- `Update: documentation for Z`
- `Refactor: improve performance of W`
- `Test: add tests for V`

## Questions?

Feel free to open an issue for any questions or join the discussion!

## Code of Conduct

Be respectful, constructive, and collaborative. We're all here to improve security!

---

Thank you for contributing to SOC Analyst AI! 🛡️
