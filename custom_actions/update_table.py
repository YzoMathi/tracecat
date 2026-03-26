from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Annotated
from typing_extensions import Doc

from tracecat_registry import registry


@registry.register(
    default_title="Update Alert Table",
    description="Create a markdown table for main or consolidated alerts",
    display_group="Table update",
    namespace="integrations.ax",
)


def update_alert_table(
    matches: Annotated[list, Doc("List of events")], text: Annotated[str, Doc("Table")]):
    """
    Appends unique rows to the existing Markdown table for 'main' alerts.
    matches: List of event dictionaries.
    text: The existing Markdown text (table).
    """
    
    # Ensure matches is a list
    if isinstance(matches, dict):
        matches = [matches]
    if not matches:
        return text

    # --- HELPER: Deep extraction ---
    def get_nested(data, path):
        if path in data:
            return data[path]
        
        keys = path.split('.')
        val = data
        try:
            for key in keys:
                if isinstance(val, dict):
                    val = val.get(key)
                else:
                    return None
            return val
        except:
            return None

    def adjust_time(ts_str):
        formatted_time = "N/A"
        SYSTEM_TZ = "Europe/Prague"
        try:
            if ts_str:
                dt_utc = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=ZoneInfo("UTC"))
                dt_local = dt_utc.astimezone(ZoneInfo(SYSTEM_TZ))
                formatted_time = dt_local.strftime("%Y-%m-%d %H:%M:%S")
                return formatted_time
        except:
                # Fallback to the raw timestamp from the current event
            formatted_time = str(event_data.get("@timestamp", "N/A"))
            return formatted_time
    # --- MAIN LOOP ---
    for event_data in matches:

        # --- HELPER: Timezone Conversion (Defined here to access event_data scope) ---
        
        # 1. Extract Fields matching the "Main" table structure
        timestamp = adjust_time(event_data.get("@timestamp", ""))
        created   = adjust_time(get_nested(event_data,"event.created"))

        rule_name = get_nested(event_data, "rule.name") or "-"
        severity  = get_nested(event_data, "severity") or "-"
        reference = get_nested(event_data, "rule.reference") or "-"
        tactic    = get_nested(event_data, "kibana.alert.rule.threat.tactic.name") or "-"

        # 2. Check Uniqueness (using core fields)
        test_row = f"{rule_name} | {severity} | {reference} | {tactic}"
        
        core_rule_name = rule_name.split(' ')[0] 

        if core_rule_name not in text:
            # 3. Construct the Full Row
            row = f"| {timestamp} | {created} | {rule_name} | {severity} | {reference} | {tactic} |"
            
            # Ensure we start on a new line if the text doesn't end with one
            if len(text) > 0 and not text.endswith('\n'):
                text += "\n"
            
            text += row

    return text