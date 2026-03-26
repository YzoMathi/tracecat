from typing import Annotated
from typing_extensions import Doc
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
import json

from tracecat_registry import registry

@registry.register(
    default_title="Create Alert Detail Table",
    description="Create a vertical HTML detail table for a security alert payload",
    display_group="Table creation",
    namespace="integrations.ax",
)
def create_comment_table(inputs: Annotated[dict, Doc("The alert object (payload[0])")]):
    # ------------------------------------------------------------------
    # HELPER: Timezone Adjustment
    # ------------------------------------------------------------------
    def adjust_time(ts_str):
        if not ts_str or ts_str in ["-", "N/A", ""]:
            return "-"
        SYSTEM_TZ = "Europe/Prague"
        try:
            # Handles '2026-02-16T08:24:20.328Z'
            dt_utc = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=ZoneInfo("UTC"))
            dt_local = dt_utc.astimezone(ZoneInfo(SYSTEM_TZ))
            return dt_local.strftime("%Y-%m-%d %H:%M:%S")
        except:
            try:
                # Handles '2026-02-16T08:24:20Z'
                dt_utc = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=ZoneInfo("UTC"))
                dt_local = dt_utc.astimezone(ZoneInfo(SYSTEM_TZ))
                return dt_local.strftime("%Y-%m-%d %H:%M:%S")
            except:
                return str(ts_str)

    # ------------------------------------------------------------------
    # HELPER: Nested Data Extraction
    # ------------------------------------------------------------------
    def get_nested(data, path):
        if not data or not isinstance(data, dict):
            return None
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

    # ------------------------------------------------------------------
    # 1. DATA SELECTION
    # ------------------------------------------------------------------
    # Since you pass payload[0], event_data is the input itself
    event_data = inputs if isinstance(inputs, dict) else {}
    
    if not event_data:
        return "<div style='color: #ffffff;'>No alert data found in payload.</div>"

    # ------------------------------------------------------------------
    # 2. STYLES
    # ------------------------------------------------------------------
    CONTAINER_STYLE = "font-family: 'Segoe UI', Arial, sans-serif; border: 1px solid #444444; border-radius: 6px; padding: 16px; color: #ffffff; background-color: #1a1a1a;"
    TITLE_STYLE = "margin-top: 0; margin-bottom: 12px; font-size: 18px; font-weight: bold; color: #ffffff; border-bottom: 1px solid #444444; padding-bottom: 8px;"
    TABLE_STYLE = "width: 100%; border-collapse: collapse; font-size: 13px; color: #ffffff;"
    LABEL_STYLE = "color: #aaaaaa; font-weight: bold; padding: 10px 5px; border-bottom: 1px solid #333333; width: 30%; text-align: left; vertical-align: top; text-transform: uppercase; font-size: 11px;"
    VALUE_STYLE = "color: #eeeeee; padding: 10px 5px; border-bottom: 1px solid #333333; vertical-align: top; word-break: break-all;"
    LINK_STYLE = "color: #4dabff; text-decoration: none; font-weight: bold;"

    # ------------------------------------------------------------------
    # 3. FIELD MAPPING
    # ------------------------------------------------------------------
    fields_map = [
        ("Time", "@timestamp"),
        ("Rule Name", "rule.name"),
        ("Rule Description", "rule.description"),
        ("Rule Reference", "rule.reference"),
        ("Threat Tactic", "kibana.alert.rule.threat.tactic.name"),
        ("Event Provider", "event.provider"), 
        ("Hostname", "host.name"),
        ("Event Code", "event.code"),
        ("Rule Category", "rule.category"),
        ("Detection ID", "_id"),
        ("Event ID", "winlog.event_id"),
        ("Computer Name", "winlog.computer_name"),
        ("Logon Type", "winlog.event_data.LogonType"),
        ("Target User Name", "winlog.event_data.TargetUserName"),
        ("Target Domain Name", "winlog.event_data.TargetDomainName"),        
        ("Subject User Name", "winlog.event_data.SubjectUserName"),
        ("Process Name", "winlog.event_data.ProcessName"),
        ("IP Address", "winlog.event_data.IpAddress"),
        ("Status", "winlog.event_data.Status"),
        ("Kibana Discovery", "kibana_discover_url")
    ]

    # ------------------------------------------------------------------
    # 4. BUILD HTML
    # ------------------------------------------------------------------
    html = f"""
    <div style="{CONTAINER_STYLE}">
        <h3 style="{TITLE_STYLE}">Alert Investigation: {get_nested(event_data, 'rule.name') or 'Security Event'}</h3>
        <table style="{TABLE_STYLE}">
            <tbody>
    """

    for label, path in fields_map:
        if path == "@timestamp":
            val = adjust_time(event_data.get("@timestamp"))
        else:
            val = get_nested(event_data, path)

        if val is not None and str(val).strip() not in ["", "-", "None"]:
            # Format URLs as clickable links
            if isinstance(val, str) and val.startswith("http"):
                val_display = f'<a href="{val}" target="_blank" style="{LINK_STYLE}">Open Link</a>'
            else:
                val_display = str(val)

            html += f"""
                <tr>
                    <td style="{LABEL_STYLE}">{label}</td>
                    <td style="{VALUE_STYLE}">{val_display}</td>
                </tr>
            """

    html += """
            </tbody>
        </table>
    </div>
    """

    return html