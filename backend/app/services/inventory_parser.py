import csv
import json
import io
from typing import Dict, Any, List, Tuple

class InventoryParseException(Exception):
    pass

class InventoryParser:
    @staticmethod
    def parse_json(content: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Parse structured JSON inventory containing 'packages' and optional 'configuration_metadata'."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise InventoryParseException(f"Invalid JSON format: {str(e)}")

        if isinstance(data, list):
            # Direct list of packages
            packages = []
            for item in data:
                if isinstance(item, dict) and "name" in item:
                    packages.append({
                        "name": str(item.get("name", "")).strip(),
                        "version": str(item.get("version", "")).strip(),
                        "architecture": str(item.get("architecture", "x86_64")).strip(),
                        "status": str(item.get("status", "installed")).strip(),
                        "description": str(item.get("description", "")).strip(),
                    })
            return packages, {}

        if isinstance(data, dict):
            raw_packages = data.get("packages", [])
            packages = []
            for item in raw_packages:
                if isinstance(item, dict) and "name" in item:
                    packages.append({
                        "name": str(item.get("name", "")).strip(),
                        "version": str(item.get("version", "")).strip(),
                        "architecture": str(item.get("architecture", "x86_64")).strip(),
                        "status": str(item.get("status", "installed")).strip(),
                        "description": str(item.get("description", "")).strip(),
                    })
            config_meta = data.get("configuration_metadata", {})
            return packages, config_meta

        raise InventoryParseException("JSON root must be an object or a list of packages")

    @staticmethod
    def parse_csv(content: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Parse CSV inventory containing columns: package_name/name, version, [architecture], [status]."""
        packages = []
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                # Find name column
                name = row.get("package_name") or row.get("name") or row.get("Package") or row.get("Software")
                version = row.get("version") or row.get("Version") or row.get("InstalledVersion")
                if name and version:
                    packages.append({
                        "name": name.strip(),
                        "version": version.strip(),
                        "architecture": (row.get("architecture") or row.get("arch") or "x86_64").strip(),
                        "status": (row.get("status") or "installed").strip(),
                        "description": (row.get("description") or "").strip(),
                    })
        except Exception as e:
            raise InventoryParseException(f"CSV parsing error: {str(e)}")

        if not packages:
            raise InventoryParseException("No valid packages found in CSV. Expected headers: 'package_name' or 'name', and 'version'.")

        return packages, {}
