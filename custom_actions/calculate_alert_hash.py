from typing import Annotated
from typing_extensions import Doc
import hashlib
import json

from tracecat_registry import registry


@registry.register(
    default_title="Calculate Alert Hash",
    description="Compute a deterministic BLAKE2s hash across specified alert JSON fields.",
    display_group="Alert Processing",
    namespace="integrations.ax",
)


def generate_alert_hash(
    alert: Annotated[dict, Doc("The alert JSON object to hash from")],
):
    #Serialize dict->json string
    # json_str = json.dumps(alert)

    to_hash = {}
    to_hash["hostname"] = alert["host"]["name"]
    to_hash["customer"] = alert["_index"]

    # Deterministically serialize the dict to string
    to_hash_str = json.dumps(to_hash, sort_keys=True, separators=(",", ":"))

    # Compute the BLAKE2s hash
    h = hashlib.blake2s(to_hash_str.encode()).hexdigest()

    # Return hash string
    return h