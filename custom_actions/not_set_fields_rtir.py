from typing import Annotated
from typing_extensions import Doc
import json
import re

from tracecat_registry import registry

@registry.register(
    default_title="Map Unset Sanitized Rule Fields",
    description="Returns unique rule names with special characters removed where custom fields are unset.",
    display_group="Data Mapping",
    namespace="integrations.ax",
)
def get_unset_rule_names(
    payload: Annotated[list, Doc("List of alert JSON objects")],
    fields: Annotated[list, Doc("List of custom field objects")]
):
    """
    Scans the payload and returns a list of tuples for rules with unset fields.
    Each tuple contains: (Original Rule Name, Sanitized/Truncated ID)
    """
    
    def get_nested(data, path):
        if not data or not isinstance(data, dict):
            return None
        # Check for flat key first (e.g., "rule.name")
        if path in data:
            return data[path]
        # Fallback to nested
        keys = path.split('.')
        val = data
        try:
            for key in keys:
                val = val.get(key) if isinstance(val, dict) else None
            return val
        except:
            return None

    unset_results = []
    # Deduplicate based on the cleaned name to avoid redundant field updates
    seen_in_this_run = set()

    for alert in payload:
        raw_rule_name = get_nested(alert, "rule.name")
        
        if not raw_rule_name:
            continue
            
        # 1. SANITIZATION: Remove . / ( ) - — and space
        # 2. LOWERCASE: To match the fields list IDs
        # 3. TRUNCATE: Cut to 63 chars to match field ID constraints
        clean_rule_name = re.sub(r"[./()\-\—\s]", "", str(raw_rule_name)).lower() # Clean from forbiden characters in Tracecat
        clean_rule_name = clean_rule_name[:63] # Max size of custom field in Tracecat
        
        if clean_rule_name in seen_in_this_run:
            continue
            
        for field in fields:
            # Match against the sanitized ID in your fields list
            if field.get("id") == clean_rule_name:
                # Checks if the value already exists
                field_value = field.get("value") 
                if field_value is None or str(field_value).strip() == "" or str(field_value).lower() == "null":
                    # Return both the original and the cleaned version for use cases in Tracecat
                    unset_results.append((str(raw_rule_name), clean_rule_name))
                    seen_in_this_run.add(clean_rule_name)
                break

    return unset_results