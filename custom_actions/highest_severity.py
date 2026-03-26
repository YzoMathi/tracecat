from typing import Annotated
from typing_extensions import Doc
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
import re
import json
from enum import IntEnum

from tracecat_registry import registry

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

# The decorator needs to go directly above the function it modifies
@registry.register(
    default_title="Find highest severity of matches and a case",
    description="Checks severity of all cases and returns the highest one",
    display_group="Data Mapping",
    namespace="integrations.ax",
)
def find_highest_severity(
    inputs: Annotated[list, Doc("List of new alert JSON objects")], # Added missing comma
    severity: Annotated[str, Doc("Severity of main case")]          # Changed 'string' to 'str'
):
    # Convert the starting string to the IntEnum object right away
    highest_severity = Severity[severity.upper()]

    for alert in inputs:
        # Assuming 'inputs' is a list of dictionaries, use dictionary access
        # If they are actually objects with attributes, change this back to alert.severity
        alert_sev_str = alert.get("severity") 
        
        if alert_sev_str:
            current_severity = Severity[alert_sev_str.upper()]
            
            # Now we are comparing real numbers (1, 2, 3, 4)
            if current_severity > highest_severity:
                highest_severity = current_severity
                
    # .name gets the string version of the Enum (e.g., "CRITICAL")
    # .lower() converts it to "critical" as requested
    return highest_severity.name.lower()