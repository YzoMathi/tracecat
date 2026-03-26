from typing import Annotated
from typing_extensions import Doc
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib
import json

from tracecat_registry import registry


@registry.register(
    default_title="Create Alert Markdown Table",
    description="Create a markdown table for main or consolidated alerts",
    display_group="Table creation",
    namespace="integrations.ax",
)

def create_markdown_table(
    TRIGGER: Annotated[dict, Doc("The alert JSON object to create the table from")], table_type: Annotated[str, Doc("Accepts 'main' or 'comment' values")]
    ):

    # Handles if data is inside a 'matches' list or directly in the root
    if 'matches' in TRIGGER and isinstance(TRIGGER['matches'], list) and len(TRIGGER['matches']) > 0:
        event_data = TRIGGER['matches'][0]
    
    elif 'payload' in TRIGGER and isinstance(TRIGGER['payload'], list) and len(TRIGGER['payload']) > 0:
        event_data = TRIGGER['payload'][0]
    
    else:
        event_data = TRIGGER

    # Digs through the JSON (e.g., winlog -> event_data -> TargetSid)
    def get_nested(data, path):
        
        if path in data: #Ignores "." characters if they are in the path, returns the dict directly
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
            formatted_time = str(event_data.get("@timestamp", "N/A"))
            return formatted_time

    #Builds the table
    lines = []

    # Main case table
    if table_type == "main":
        timestamp = adjust_time(event_data.get("@timestamp", ""))
        created   = adjust_time(event_data.get("event.created", ""))
        rule_name = get_nested(event_data, "rule.name")
        severity  = get_nested(event_data, "severity")
        reference = get_nested(event_data, "rule.reference")
        tactic    = get_nested(event_data, "kibana.alert.rule.threat.tactic.name")
        
        row = f"| {timestamp} | {created} | {rule_name} | {severity} | {reference} | {tactic} |"
        lines.append(row)

    # Comment table
    if table_type == "comment":
        #Field mapping - this sorts the field in the table
        fields_map = [
            ("Time", "@timestamp"),
            ("SEPARATOR", "SEPARATOR"),
            ("Rule Name", "rule.name"),
            ("Severity", "severity"),
            ("Rule Reference", "rule.reference"),
            ("Rule Threat Name", "kibana.alert.rule.threat.tactic.name"),
            ("Event Provider", "event.provider"), 
            ("Hostname", "host.name"),
            ("Event code", "event.code"),
            ("Rule category", "rule.category"),
            ("Threat ID", "kibana.alert.rule.threat.tactic.id"),
            ("Event logs", "kibana_discover_url"),
            ("Rule Threat Reference", "kibana.alert.rule.threat.tactic.reference"),
            ("Detection ID", "_id"),
            ("Event ID", "winlog.event_id"),
            ("Computer name", "winlog.computer_name"),
            ("Activity ID", "winlog.activity_id"),
            ("Target SID", "winlog.event_data.TargetSid"),
            ("Target User SID", "winlog.event_data.TargetUserSid"),
            ("Target User Name", "winlog.event_data.TargetUserName"),
            ("New Target User Name", "winlog.event_data.NewTargetUserName"),
            ("Target Domain Name", "winlog.event_data.TargetDomainName"),        
            ("Member Sid", "winlog.event_data.MemberSid"),
            ("Member Name", "winlog.event_data.MemberName"),        
            ("Subject User Name", "winlog.event_data.SubjectUserName"),
            ("Subject Domain Name", "winlog.event_data.SubjectDomainName"),
            ("Logon Type", "winlog.event_data.LogonType"),
            ("Process Name", "winlog.event_data.ProcessName"),
            ("Authentication Package Name", "winlog.event_data.AuthenticationPackageName"),        
            ("IP Address", "winlog.event_data.IpAddress"),
            ("Client Address", "winlog.event_data.ClientAddress"),
            ("Status", "winlog.event_data.Status"),
            ("SubStatus", "winlog.event_data.SubStatus"),
            ("Failure Reason", "winlog.event_data.FailureReason"),
            ("Failure Code", "winlog.event_data.FailureCode"),
            ("PreAuthType", "winlog.event_data.PreAuthType")  
        ]

        for label, path in fields_map:
            # Separator needed in the markdown table
            if label == "SEPARATOR":
                lines.append("|---|---|")
                continue

            # Get Value
            if path == "@timestamp":
                val = adjust_time(event_data.get("@timestamp", ""))
            else:
                val = get_nested(event_data, path)

            # Only add if a value is present - if it is not None, not an empty string, and not just a dash "-"
            if val is not None and str(val).strip() != "" and str(val).strip() != "-":
                lines.append(f"| **{label}** | {val} |")

    # Return result
    if not lines:
        return "No matching data found."
        
    return "\n".join(lines)