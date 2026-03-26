import sys
import urllib.parse
import re
import requests
from requests.auth import HTTPBasicAuth
from typing import List, Dict, Any, Annotated
from typing_extensions import Doc
from tracecat_registry import registry

@registry.register(
    default_title="Get Logs From Kibana Link",
    description="Get all alert triggering logs from Elasticsearch",
    display_group="Kibana",
    namespace="integrations.ax",
)
def fetch_elastic_logs(
    kibana_url: Annotated[str, Doc("The existing Kibana URL")],
    user: Annotated[str, Doc("Username for elastic")],
    password: Annotated[str, Doc("Password for elastic")],
) -> List[Dict[str, Any]]: # Tells Tracecat this outputs a list of dictionaries

    decoded_url = urllib.parse.unquote(kibana_url)

    # 1. Extract the Time Range
    time_match = re.search(r"time:\(from:'(.*?)',to:'(.*?)'\)", decoded_url)
    if not time_match:
        # Raise an exception so the Tracecat node officially registers a failure
        raise ValueError("Error: Could not find the time range in the provided URL.")
    
    time_from = time_match.group(1)
    time_to = time_match.group(2)
    
    # 2. Extract the Query
    query_match = re.search(r"query:'(.*?)'", decoded_url)
    if not query_match:
        raise ValueError("Error: Could not find the query string in the provided URL.")
        
    kibana_query = query_match.group(1)

    # 3. Build the Elasticsearch Payload
    payload = {
        "size": 10000,
        "_source": {
            "excludes": [
                "event.message",
                "event.original",
                "message",
                "rule_param_description",
                "rule_param_rule.reference.keyword",
                "kibana_discover_url",
                "ecs",
                "@version",
                "environment",
                "rule_param_kibana.alert.rule.threat.tactic.id",
                "rule_param_kibana.alert.rule.threat.tactic.name",
                "rule_param_kibana.alert.rule.threat.tactic.refenrence",
                "rule_param_kibana.alert.rule.type",
                "rule_param_kibana.alert.rule.threat.tactic.reference",
                "rule_param_category",
                "rule_param_owner",
                "rule_param_rule.version",
                "rule_param_rule.reference",
                "winlog.version",
                "winlog.process",
                "agent",
                "host",
                "winlog.provider_guid",
                "log",
                "winlog.opcode",
                "winlog.record_id",
                "platform",
                "winlog.task",
                "winlog.keywords"
            ]
        },
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": kibana_query}},
                    {"range": {"@timestamp": {"gte": time_from, "lte": time_to, "format": "strict_date_optional_time"}}}
                ]
            }
        }
    }

    # 4. Fetch the data from Elasticsearch (Using FQDN for cross-namespace K8s routing!)
    es_host_url = "https://my-elastic-elasticsearch:9201" 
    es_index = "elastalert_forwarded" 
    es_endpoint = f"{es_host_url}/{es_index}/_search"
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(
            es_endpoint, 
            auth=HTTPBasicAuth(user,password), 
            headers=headers, 
            json=payload, 
            verify=False 
        )
        
        # Automatically raise an exception if ES returns a 401, 404, 500, etc.
        response.raise_for_status() 
        
        data = response.json()
        logs = data.get('hits', {}).get('hits', [])
        
        # RETURN the actual _source data so Tracecat can pass it to the next node
        return [log['_source'] for log in logs]

    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection to Elasticsearch failed: {e}")
