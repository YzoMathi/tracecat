from typing import Annotated
from typing_extensions import Doc
import json

from tracecat_registry import registry

@registry.register(
    default_title="Get Custom Field Value",
    description="Finds a field by ID in the custom fields list and returns its value.",
    display_group="Data Mapping",
    namespace="integrations.ax",
)
def get_custom_field_value(
    fields: Annotated[list, Doc("The list of custom field objects")],
    field_name: Annotated[str, Doc("The ID/name of the field to search for")]
):
    """
    Iterates through the fields list. If a field's 'id' matches field_name,
    it returns the 'value' of that field.
    """
    if not fields or not isinstance(fields, list):
        return None

    for field in fields:
        # Check if the 'id' of the current field object matches the requested name
        if field.get("id") == field_name:
            return field.get("value")

    # Return None if the field name was not found in the list
    return None
