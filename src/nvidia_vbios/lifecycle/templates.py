"""Installed-wheel hook templates; no checkout path is required."""
from importlib.resources import files
import json
from .security import LifecycleError


def hook_templates(*, resource_bytes=None):
    """Return {absolute_destination: {data: bytes, mode: int}} for bootstrap.

    The JSON resource carries all template text, including timer/action suffixes
    which older package-data globs omit. Kernel hook and units execute only the
    root-installed runner; resource loading never activates them.
    """
    text = files("nvidia_vbios.lifecycle").joinpath("hook_templates.json").read_text() if resource_bytes is None else resource_bytes
    resource = json.loads(text)
    if resource.get("schema_version") != 1:
        raise LifecycleError("unsupported lifecycle template resource")
    return {entry["destination"]: {"data": entry["text"].encode(), "mode": entry["mode"]}
            for entry in resource["templates"]}
