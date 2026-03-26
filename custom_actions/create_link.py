import re
import requests
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse
from typing import List, Dict, Any, Annotated
from typing_extensions import Doc
from tracecat_registry import registry

from tracecat_registry import registry

@registry.register(
    default_title="Create Kibana Link",
    description="Create a link and short link",
    display_group="Link creation",
    namespace="integrations.ax",
)


def create_kibana_link(
    matches: Annotated[List[Dict[str, Any]], Doc("A list of events")],
    link: Annotated[str, Doc("The existing Kibana URL or nothing")],
    api_key: Annotated[str, Doc("Kibana API Key from secret store")]
):
    # 1. CONFIGURATION
    kibana_domain = "https://kibana.soc2027.secopnet.com"
    # Use the UUID from your requirement for the Data View
    index_pattern_id = "19688c57-6583-48da-9c36-bdf74f2a6536"
    
    base_path = "/app/discover#/"
    base_url = f"{kibana_domain}{base_path}"
    
    id_pool = set()
    timestamps = []

    # --- PROCESS OLD LINK ---
    if link and isinstance(link, str) and len(link) > 10:
        decoded_url = unquote(link)
        existing_ids = re.findall(r'winlog\.record_id:"([^"]+)"', decoded_url)
        id_pool.update(existing_ids)
        
        old_start_match = re.search(r"from:'([^']+)'", decoded_url)
        if old_start_match:
            timestamps.append(old_start_match.group(1))

    # --- PROCESS NEW MATCHES ---
    if isinstance(matches, dict):
        matches = [matches]
    
    if matches:
        for event in matches:
            rid = event.get('winlog.record_id') or event.get('winlog', {}).get('record_id')
            if rid:
                id_pool.add(str(rid))
            
            ts = event.get('@timestamp')
            if ts:
                timestamps.append(ts)

    # --- CALCULATE TIME WINDOW WITH +- 1 MINUTE ---
    if timestamps:
        # Convert strings to datetime objects for math
        # Handles typical ISO format: 2023-10-27T10:00:00.000Z
        dt_objs = []
        for t in timestamps:
            try:
                # Strip 'Z' and replace with +00:00 for fromisoformat
                clean_ts = t.replace('Z', '+00:00')
                dt_objs.append(datetime.fromisoformat(clean_ts))
            except ValueError:
                continue

        if dt_objs:
            # Apply the 1-minute buffers
            start_dt = min(dt_objs) - timedelta(minutes=1)
            end_dt = max(dt_objs) + timedelta(minutes=1)
            
            # Format back to Kibana's preferred ISO string
            start_time = start_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_time = end_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        else:
            start_time, end_time = "now-24h", "now"
    else:
        start_time, end_time = "now-24h", "now"

    # --- BUILD LONG URL ---
    if not id_pool:
        return {"long_url": link, "short_url": None}

    query_parts = [f'winlog.record_id:"{rid}"' for rid in id_pool]
    full_query = " OR ".join(query_parts)

    # Columns requested
    cols = (
        "host.name,event.kind,event.provider,logsource,event.action,event.outcome,"
        "winlog.event_data.TargetUserName,winlog.event_data.IpAddress,"
        "winlog.event_data.IpPort,winlog.event_data.LogonType,"
        "winlog.event_data.Status,winlog.event_data.SubStatus"
    )

    final_link = (
        f"{base_url}?_g=(time:(from:'{start_time}',to:'{end_time}'))"
        f"&_a=(columns:!({cols}),"
        f"dataSource:(dataViewId:'{index_pattern_id}',type:dataView),"
        f"filters:!(),interval:auto,"
        f"query:(language:kuery,query:'{full_query}'),sort:!())"
    )

    # --- GENERATE SHORT URL (API CALL) ---
    short_link = None
    try:
        # 1. Use the NEW API endpoint (Kibana 7.16+)
        shorten_api_url = f"{kibana_domain}/api/short_url"
        
        # 2. Prepare the relative URL (Must start with /)
        # Using urlparse ensures we cleanly strip the domain regardless of formatting
        parsed_url = urlparse(final_link)
        relative_url = parsed_url.path + "#/" + parsed_url.fragment.lstrip("/")

        # 3. Headers with Auth
        headers = {
            "kbn-xsrf": "true", 
            "Content-Type": "application/json",
            "Authorization": f"ApiKey {api_key}" # Or "Basic <base64>"
        }

        # 4. New Payload Structure
        # The 'locatorId' tells Kibana to treat this as a standard legacy URL
        payload = {
            "locatorId": "LEGACY_SHORT_URL_LOCATOR",
            "params": {
                "url": relative_url
            }
        }

        response = requests.post(
            shorten_api_url, 
            json=payload, 
            headers=headers,
            timeout=10,
            verify=True # Set to False only if using self-signed certs
        )

        if response.status_code == 200:
            data = response.json()
            # The new API returns 'id', not 'urlId'
            url_id = data.get("id") 
            if url_id:
                short_link = f"{kibana_domain}/goto/{url_id}"
        else:
            print(f"Kibana API Error: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Failed to shorten URL: {str(e)}")

    return {
        "long_url": final_link,
        "short_url": short_link 
    }