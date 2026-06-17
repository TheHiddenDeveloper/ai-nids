"""
================================================================================
JSON UTILITIES — NumPy-Safe JSON Encoding
================================================================================
Purpose:
  Single source for numpy-safe JSON serialization. The NumpyEncoder handles
  numpy ints, floats, arrays, and bools — converting them to native Python
  types before JSON encoding.

  Used by EventBus for Redis pub/sub serialization and by Monitor loggers
  for JSONL output.

Usage:
  from core.json_utils import NumpyEncoder
  json.dumps(data, cls=NumpyEncoder)
================================================================================
"""

import json
import numpy as np


class NumpyEncoder(json.JSONEncoder):
    """Converts numpy scalars and arrays to native Python types."""
    def default(self, obj):
        if isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        if isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)
