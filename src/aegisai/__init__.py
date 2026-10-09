"""AegisAI compiler and bounded-authority runtime."""
from .compiler import compile_source, check_source, run_source

__version__ = "0.5.0"
__all__ = ["compile_source", "check_source", "run_source", "__version__"]
