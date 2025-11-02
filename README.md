# sparetools-base

SpareTools foundation package - shared utilities and helpers for the SpareTools ecosystem.

## Package: `sparetools-base/1.0.0`

**Type:** `python-require`  
**Purpose:** Foundation utilities for all SpareTools packages

### Provides

- **Zero-copy symlink utilities** (`symlink-helpers.py`)
- **Security scanning gates** (`security-gates.py`) 
- **CPython bootstrap helpers** (`python_requires/cpy_helpers.py`)

### Usage

```python
from conan import ConanFile

class MyProject(ConanFile):
    python_requires = "sparetools-base/1.0.0"
    
    def build(self):
        # Access utilities via python_requires
        base = self.python_requires["sparetools-base"].module
        base.symlink_helpers.create_zero_copy_environment(
            self, "sparetools-cpython", "./TOOLS/python"
        )
```

### Related Packages

- `sparetools-cpython/3.12.7` - Prebuilt CPython
- Part of [sparetools](https://github.com/sparesparrow/sparetools) ecosystem
