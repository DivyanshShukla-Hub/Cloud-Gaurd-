import json
import yaml
import os

class ParseError(Exception):
    pass

def parse_config(filepath):
    """Parse a JSON or YAML config file. Returns (dict, filetype_str)."""
    if not os.path.exists(filepath):
        raise ParseError("File not found.")

    ext = os.path.splitext(filepath)[1].lower()

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw = f.read()
    except UnicodeDecodeError:
        raise ParseError("Uploaded file must be valid UTF-8 text.")

    if not raw.strip():
        raise ParseError("Uploaded file is empty.")

    try:
        if ext == ".json":
            data = json.loads(raw)
            ftype = "JSON"
        elif ext in (".yaml", ".yml"):
            data = yaml.safe_load(raw)
            ftype = "YAML"
        else:
            raise ParseError(f"Unsupported file type: {ext}")
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")
    except yaml.YAMLError as e:
        raise ParseError(f"Invalid YAML: {e}")

    if not isinstance(data, dict):
        raise ParseError("Config must be a JSON/YAML object (not a list or scalar).")

    return data, ftype
