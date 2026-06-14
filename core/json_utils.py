"""
Shared JSON utilities — single source for numpy-safe encoding.
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
