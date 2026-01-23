# Publishing homelocal-auth

## Prerequisites

1. Access to private PyPI registry (GitHub Packages, Artifactory, or similar)
2. Python 3.11+ with `build` and `twine` installed

## Build

```bash
cd packages/homelocal-auth

# Install build tools
pip install build twine

# Build package
python -m build

# This creates:
#   dist/homelocal_auth-0.1.0-py3-none-any.whl
#   dist/homelocal_auth-0.1.0.tar.gz
```

## Publishing Options

### Option A: GitHub Packages (Recommended)

1. **Create a Personal Access Token (PAT)** with `write:packages` scope

2. **Configure pip for GitHub Packages:**
   ```bash
   # ~/.pypirc
   [distutils]
   index-servers = github

   [github]
   repository = https://upload.pypi.org/legacy/
   username = __token__
   password = ghp_YOUR_GITHUB_PAT
   ```

3. **Publish:**
   ```bash
   python -m twine upload --repository github dist/*
   ```

4. **Consumer configuration:**
   ```bash
   # In consuming service's requirements.txt or pyproject.toml
   pip install homelocal-auth==0.1.0 \
     --index-url https://pypi.org/simple/ \
     --extra-index-url https://YOUR_PAT@ghcr.io/homelocal/
   ```

### Option B: Private PyPI Server (pypiserver, Artifactory)

1. **Configure credentials:**
   ```bash
   # ~/.pypirc
   [distutils]
   index-servers = private

   [private]
   repository = https://pypi.homelocal.internal/
   username = your-username
   password = your-password
   ```

2. **Publish:**
   ```bash
   python -m twine upload --repository private dist/*
   ```

3. **Consumer configuration:**
   ```bash
   pip install homelocal-auth==0.1.0 \
     --index-url https://pypi.homelocal.internal/simple/
   ```

### Option C: AWS CodeArtifact

1. **Get auth token:**
   ```bash
   aws codeartifact login --tool pip --domain homelocal --repository python
   ```

2. **Publish:**
   ```bash
   python -m twine upload \
     --repository-url https://homelocal-123456789.d.codeartifact.us-east-1.amazonaws.com/pypi/python/ \
     dist/*
   ```

## Versioning

Update version in `pyproject.toml`:

```toml
[project]
version = "0.1.0"  # Bump this
```

Follow semantic versioning:
- **Patch** (0.1.1): Bug fixes, no API changes
- **Minor** (0.2.0): New features, backwards compatible
- **Major** (1.0.0): Breaking API changes

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Publish Package

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install build tools
        run: pip install build twine

      - name: Build package
        working-directory: packages/homelocal-auth
        run: python -m build

      - name: Publish to GitHub Packages
        working-directory: packages/homelocal-auth
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python -m twine upload \
            --repository-url https://upload.pypi.org/legacy/ \
            dist/*
```

## Consuming in Railway-deployed Services

Add to `requirements.txt`:

```
# With GitHub Packages
--extra-index-url https://${GITHUB_TOKEN}@ghcr.io/homelocal/
homelocal-auth==0.1.0

# Or with private PyPI
--index-url https://pypi.homelocal.internal/simple/
homelocal-auth==0.1.0
```

Or in `pyproject.toml`:

```toml
[project]
dependencies = [
    "homelocal-auth==0.1.0",
]

[tool.pip]
extra-index-url = ["https://pypi.homelocal.internal/simple/"]
```

Set `GITHUB_TOKEN` or registry credentials as Railway environment variables.
