import csv
import json
import io
import re
from typing import Dict, Any, List, Tuple, Optional

class InventoryParseException(Exception):
    pass

class InventoryParser:
    @staticmethod
    def validate_inventory(packages: List[Dict[str, Any]], config_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validate parsed packages and configuration metadata.
        Returns a structured validation summary report.
        """
        total = len(packages)
        valid_items: List[Dict[str, Any]] = []
        errors: List[str] = []
        warnings: List[str] = []
        seen_names = set()
        duplicates = 0

        for idx, pkg in enumerate(packages):
            pkg_name = str(pkg.get("name", "")).strip()
            pkg_ver = str(pkg.get("version", "")).strip()

            if not pkg_name:
                errors.append(f"Row/Item #{idx + 1}: Package name is empty or missing.")
                continue

            if not pkg_ver:
                errors.append(f"Row/Item #{idx + 1} ({pkg_name}): Package version is empty or missing.")
                continue

            # Check for illegal control characters
            if re.search(r"[\x00-\x1f\x7f]", pkg_name):
                errors.append(f"Row/Item #{idx + 1} ({pkg_name}): Contains illegal control characters.")
                continue

            # Track duplicate package names
            lowered_name = pkg_name.lower()
            if lowered_name in seen_names:
                duplicates += 1
                warnings.append(f"Duplicate package declaration: '{pkg_name}' appears multiple times.")
            else:
                seen_names.add(lowered_name)

            valid_items.append(pkg)

        if total == 0:
            errors.append("Inventory is empty; at least one package or component must be present.")

        is_valid = len(errors) == 0 and len(valid_items) > 0

        return {
            "is_valid": is_valid,
            "total_packages": total,
            "valid_packages_count": len(valid_items),
            "invalid_packages_count": total - len(valid_items),
            "duplicate_count": duplicates,
            "unique_components_count": len(seen_names),
            "errors": errors,
            "warnings": warnings,
            "configuration_keys": list((config_meta or {}).keys())
        }

    @staticmethod
    def parse_json(content: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Parse structured JSON inventory containing 'packages' and optional 'configuration_metadata'."""
        if not content or not content.strip():
            raise InventoryParseException("Inventory JSON content cannot be empty.")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise InventoryParseException(f"Invalid JSON format: {str(e)}")

        packages: List[Dict[str, Any]] = []
        config_meta: Dict[str, Any] = {}

        if isinstance(data, list):
            # Direct list of packages
            for item in data:
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("package_name") or item.get("package") or "").strip()
                    ver = str(item.get("version") or item.get("installed_version") or "").strip()
                    if name:
                        packages.append({
                            "name": name,
                            "version": ver,
                            "architecture": str(item.get("architecture") or item.get("arch") or "x86_64").strip(),
                            "status": str(item.get("status") or "installed").strip(),
                            "description": str(item.get("description") or "").strip(),
                        })
            return packages, {}

        if isinstance(data, dict):
            raw_packages = data.get("packages") or data.get("inventory") or data.get("installed_software") or []
            if not isinstance(raw_packages, list):
                raise InventoryParseException("Field 'packages' must be a JSON array.")

            for item in raw_packages:
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("package_name") or item.get("package") or "").strip()
                    ver = str(item.get("version") or item.get("installed_version") or "").strip()
                    if name:
                        packages.append({
                            "name": name,
                            "version": ver,
                            "architecture": str(item.get("architecture") or item.get("arch") or "x86_64").strip(),
                            "status": str(item.get("status") or "installed").strip(),
                            "description": str(item.get("description") or "").strip(),
                        })

            config_meta = data.get("configuration_metadata", {})
            if not isinstance(config_meta, dict):
                config_meta = {}

            return packages, config_meta

        raise InventoryParseException("JSON root must be an object or a list of packages.")

    @staticmethod
    def parse_csv(content: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Parse CSV inventory containing columns: package_name/name, version, [architecture], [status]."""
        if not content or not content.strip():
            raise InventoryParseException("Inventory CSV content cannot be empty.")

        packages = []
        # Filter out comment lines starting with #
        lines = [line for line in content.splitlines() if not line.strip().startswith("#")]
        clean_content = "\n".join(lines)

        try:
            reader = csv.DictReader(io.StringIO(clean_content))
            if not reader.fieldnames:
                raise InventoryParseException("CSV must contain a header row specifying column names.")

            # Map headers case-insensitively
            header_map = {fn.strip().lower(): fn for fn in reader.fieldnames if fn}

            def get_field(row_dict: dict, *candidates: str) -> str:
                for cand in candidates:
                    low = cand.lower()
                    if low in header_map:
                        val = row_dict.get(header_map[low])
                        if val is not None and str(val).strip():
                            return str(val).strip()
                return ""

            for row in reader:
                name = get_field(row, "package_name", "name", "package", "software", "app", "component", "id")
                version = get_field(row, "version", "ver", "installedversion", "installed_version", "pkg_version")

                if name or version:
                    arch = get_field(row, "architecture", "arch", "platform") or "x86_64"
                    status_val = get_field(row, "status", "state", "install_state") or "installed"
                    desc = get_field(row, "description", "desc", "summary") or ""

                    packages.append({
                        "name": name,
                        "version": version,
                        "architecture": arch,
                        "status": status_val,
                        "description": desc,
                    })
        except Exception as e:
            if isinstance(e, InventoryParseException):
                raise
            raise InventoryParseException(f"CSV parsing error: {str(e)}")

        if not packages:
            raise InventoryParseException("No valid packages found in CSV. Expected headers: 'package_name' or 'name', and 'version'.")

        return packages, {}
