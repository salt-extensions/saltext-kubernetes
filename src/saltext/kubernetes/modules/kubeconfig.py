"""Safely merge structured data into Kubernetes kubeconfig files."""

import copy
import os
import tempfile

import yaml
from salt.exceptions import CommandExecutionError

_BASE_CONFIG = {
    "apiVersion": "v1",
    "kind": "Config",
    "preferences": {},
    "clusters": [],
    "users": [],
    "contexts": [],
    "current-context": "",
}


def __virtual__():
    """Load this module when PyYAML is available."""
    return True


def _deep_merge(old, new):
    result = copy.deepcopy(old)
    for key, value in new.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _merge_entries(config, field, entries):
    current = config.setdefault(field, [])
    if not isinstance(current, list):
        raise CommandExecutionError(f"kubeconfig field {field!r} must be a list")
    changed = []
    for entry in entries or []:
        if not isinstance(entry, dict) or not entry.get("name"):
            raise CommandExecutionError(f"each {field} entry needs a non-empty name")
        name = entry["name"]
        behavior = entry.get("behavior", "merge")
        if behavior not in ("merge", "replace", "keep", "remove"):
            raise CommandExecutionError(
                f"invalid behavior {behavior!r} for kubeconfig {field} entry {name!r}"
            )
        index = next((i for i, item in enumerate(current) if item.get("name") == name), None)
        if behavior == "remove":
            if index is not None:
                current.pop(index)
                changed.append(name)
            continue
        if behavior == "keep" and index is not None:
            continue
        value = {key: copy.deepcopy(item) for key, item in entry.items() if key != "behavior"}
        if index is None:
            current.append(value)
            changed.append(name)
        else:
            updated = _deep_merge(current[index], value) if behavior == "merge" else value
            if current[index] != updated:
                current[index] = updated
                changed.append(name)
    return changed


def merge(
    path,
    dest=None,
    clusters=None,
    users=None,
    contexts=None,
    preferences=None,
    current_context=None,
    test=False,
    mode="0600",
):
    """Merge named cluster, user, and context entries into a kubeconfig.

    ``path`` is read when it exists; otherwise a new standard kubeconfig is
    started. Entries accept ``merge`` (default), ``replace``, ``keep``, and
    ``remove`` behavior. Test mode computes changes without writing. The
    returned data contains names and paths only, never credential material.

    The output is written atomically with restrictive permissions (0600 by
    default). This function does not test whether the credentials can connect
    to a Kubernetes API server.
    """
    source = os.path.abspath(os.path.expanduser(path))
    target = os.path.abspath(os.path.expanduser(dest or path))
    try:
        if os.path.exists(source):
            with open(source, encoding="utf-8") as stream:
                config = yaml.safe_load(stream) or {}
        else:
            config = copy.deepcopy(_BASE_CONFIG)
    except (OSError, yaml.YAMLError) as exc:
        raise CommandExecutionError(f"Could not read kubeconfig at {source}") from exc
    if not isinstance(config, dict):
        raise CommandExecutionError("kubeconfig content must be a YAML mapping")

    for key, default in _BASE_CONFIG.items():
        config.setdefault(key, copy.deepcopy(default))
    changes = {}
    for field, values in (("clusters", clusters), ("users", users), ("contexts", contexts)):
        changed = _merge_entries(config, field, values)
        if changed:
            changes[field] = changed
    if preferences:
        updated = _deep_merge(config.get("preferences", {}), preferences)
        if updated != config.get("preferences", {}):
            config["preferences"] = updated
            changes["preferences"] = ["updated"]
    if current_context is not None and config.get("current-context") != current_context:
        config["current-context"] = current_context
        changes["current-context"] = [current_context]

    requested_mode = int(str(mode), 8) if isinstance(mode, str) else mode
    try:
        current_mode = os.stat(target).st_mode & 0o777
    except FileNotFoundError:
        current_mode = None
    if current_mode is not None and current_mode != requested_mode:
        changes["permissions"] = ["updated"]
    changed = bool(changes) or current_mode is None
    result = {"changed": changed, "path": target, "changes": changes}
    if not changed or test:
        return result

    directory = os.path.dirname(target) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".kubeconfig-", dir=directory)
        try:
            os.fchmod(fd, requested_mode)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                yaml.safe_dump(config, stream, default_flow_style=False, sort_keys=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, target)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise CommandExecutionError(f"Could not write kubeconfig at {target}") from exc
    return result
