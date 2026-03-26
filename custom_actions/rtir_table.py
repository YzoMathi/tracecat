from typing import Annotated
from typing_extensions import Doc
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
import re
import json

from tracecat_registry import registry

@registry.register(
    default_title="Update RTIR Unique Alert Table",
    description="Checks existing table for rules and adds only new unique rules. Returns JSON.",
    display_group="Table creation RTIR",
    namespace="integrations.ax",
)
def update_rtir_unique_table( #Returns a boolean if the table has changed, if yes returns the new table aswell.
    inputs: Annotated[list, Doc("List of new alert JSON objects")],
    current_table: Annotated[str, Doc("The existing HTML table string from the ticket")] = ""
):
    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------
    def adjust_time(ts_str): #Changes the timezone and format of datetime
        if not ts_str or ts_str in ["-", "N/A", ""]:
            return "-"
        SYSTEM_TZ = "Europe/Prague"
        try:
            dt_utc = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=ZoneInfo("UTC"))
            dt_local = dt_utc.astimezone(ZoneInfo(SYSTEM_TZ))
            return dt_local.strftime("%Y-%m-%d %H:%M:%S")
        except:
            try:
                dt_utc = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=ZoneInfo("UTC"))
                dt_local = dt_utc.astimezone(ZoneInfo(SYSTEM_TZ))
                return dt_local.strftime("%Y-%m-%d %H:%M:%S")
            except:
                return str(ts_str)

    def get_value(data, path): #Finds the value in a json
        if not data or not isinstance(data, dict):
            return None
        if path in data:
            return data[path]
        keys = path.split('.')
        val = data
        try:
            for key in keys:
                val = val.get(key) if isinstance(val, dict) else None
            return val
        except:
            return None

    # ------------------------------------------------------------------
    # 1. PARSE EXISTING RULES
    # ------------------------------------------------------------------
    existing_rules = set()
    if current_table:
        rows = re.findall(r'<tr>(.*?)</tr>', current_table, re.DOTALL) # Returns a list of rows of a table
        for row in rows:
            cells = re.findall(r'<td.*?>(.*?)</td>', row, re.DOTALL) # Returns a list of cells of a row
            if len(cells) >= 3:
                rule_name_cleaned = re.sub('<[^<]+?>', '', cells[2]).strip() # Gets the rule name
                existing_rules.add(rule_name_cleaned) # Adds the rule name to a list

    # ------------------------------------------------------------------
    # 2. STYLES & SPACERS
    # ------------------------------------------------------------------
    TABLE_STYLE = "width: 100%; border-collapse: collapse; font-size: 13px; color: #333333; font-family: Arial, sans-serif;"
    TH_STYLE = "background-color: #f2f2f2; font-weight: bold; padding: 10px; text-align: left; border: 1px solid #dddddd; white-space: nowrap;"
    TD_STYLE = "padding: 10px; border: 1px solid #dddddd; vertical-align: top;"
    LINK_STYLE = "color: #0066cc; text-decoration: underline;"

    # The "Visual Hack" spacers - Hardcoded spaces between cells (RTIR ignores some of the styles from above)
    TIME_SPACER = "&nbsp;" * 29
    TIME2_SPACER = "&nbsp;" * 10
    RULE_SPACER = "&nbsp;" * 140
    DEFAULT_SPACER = "&nbsp;" * 10

    # ------------------------------------------------------------------
    # 3. PROCESS NEW ALERTS
    # ------------------------------------------------------------------
    alerts = inputs if isinstance(inputs, list) else [inputs]
    new_rows = []
    
    for event_data in alerts:
        raw_name = get_value(event_data, "rule.name")
        if not raw_name:
            raw_name = get_value(event_data, "rule_param_name")
        
        if not raw_name or raw_name.strip() in existing_rules:
            continue
        
        existing_rules.add(raw_name.strip())
        
        end_time = adjust_time(get_value(event_data, "event.created"))
        creation_time = adjust_time(get_value(event_data, "@timestamp"))
        severity = get_value(event_data, "severity")
        if not severity:
            severity = get_value(event_data, "rule_param_severity")
        ref_url = get_value(event_data, "rule.reference")
        if not ref_url:
            ref_url = get_value(event_data, "rule_param_rule.reference")
        threat_name = get_value(event_data, "kibana.alert.rule.threat.tactic.name")
        if not threat_name:
            threat_name = get_value(event_data, "rule_param_kibana.alert.rule.threat.tactic.name")

        row_html = f"""
        <tr>
            <td style="{TD_STYLE}">{end_time}</td>
            <td style="{TD_STYLE}">{creation_time}</td>
            <td style="{TD_STYLE}">{raw_name}</td>
            <td style="{TD_STYLE}">{severity}</td>
            <td style="{TD_STYLE}"><a href="{ref_url}" target="_blank" style="{LINK_STYLE}">Link</a></td>
            <td style="{TD_STYLE}">{threat_name}</td>
        </tr>
        """
        new_rows.append(row_html)

    # ------------------------------------------------------------------
    # 4. FINAL ASSEMBLY
    # ------------------------------------------------------------------
    if new_rows:
        if not current_table or "<table" not in current_table:
            header = f"""
            <table style="{TABLE_STYLE}">
                <thead>
                    <tr>
                        <th style="{TH_STYLE}">End Time{TIME_SPACER}</th>
                        <th style="{TH_STYLE}">Alert Creation Time{TIME2_SPACER}</th>
                        <th style="{TH_STYLE}">Rule name{RULE_SPACER}</th>
                        <th style="{TH_STYLE}">Severity{DEFAULT_SPACER}</th>
                        <th style="{TH_STYLE}">Reference{DEFAULT_SPACER}</th>
                        <th style="{TH_STYLE}">Threat{DEFAULT_SPACER}</th>
                    </tr>
                </thead>
                <tbody>
            """
            updated_text = header + "\n".join(new_rows) + "</tbody></table>"
        else:
            updated_text = current_table.replace("</tbody>", "\n".join(new_rows) + "</tbody>")
            
        return {
            "changed": True,
            "text": updated_text.strip()
        }
    
    return {
        "changed": False,
        "text": current_table if current_table else None
    }