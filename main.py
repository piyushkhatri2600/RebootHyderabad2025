import base64
import json
from google.cloud import bigquery
import functions_framework

# Constants for Hackathon Project
PROJECT_ID = "ltc-reboot25-team-36"
SCAN_TABLE_ID = f"{PROJECT_ID}.sensitive_data_protection_discovery.discovery_profiles"
TARGET_TABLE_ID = f"{PROJECT_ID}.team403.sensitive_data"

# Policy tag mappings
POLICY_TAGS = {
    "PSI": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/8941678276529892128",
    "account_psi": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/3017835211807188399",
    "ssn_psi": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/4624378549843899554",
    "PII": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/4035765104472244969",
    "communication_pii": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/1441690488331269650",
    "name_pii": "projects/ltc-reboot25-team-36/locations/europe-west2/taxonomies/3218697126495470170/policyTags/6113042750445666380"
}

# Function to map DLP score with Data Catalog Policy Tags
def get_policy_tag(field_name: str, score: str):
    name = field_name.lower()
    if score == "SENSITIVITY_HIGH":
        if "ssn" in name:
            return POLICY_TAGS["ssn_psi"]
        elif "account" in name:
            return POLICY_TAGS["account_psi"]
        elif "credit_card" in name:
            return POLICY_TAGS["ssn_psi"]
        elif "passport" in name:
            return POLICY_TAGS["ssn_psi"]
        else:
            return POLICY_TAGS["PSI"]
    elif score == "SENSITIVITY_MODERATE":
        if "name" in name:
            return POLICY_TAGS["name_pii"]
        elif any(k in name for k in ["email", "phone", "contact", "mobile", "address"]):
            return POLICY_TAGS["communication_pii"]
        else:
            return POLICY_TAGS["PII"]
    return None

# Function to read DLP Scan report from BigQuery
def get_sensitivity_map(bq_client):
    query = f"""
        SELECT 
            column_profile.column AS column_name,
            column_profile.sensitivity_score.score AS score
        FROM `{SCAN_TABLE_ID}`
        WHERE column_profile.column IS NOT NULL
    """
    results = bq_client.query(query).result()
    return {row.column_name: row.score for row in results}

# Function to apply Policy tag
def apply_policy_tags(bq_client, table_id, sensitivity_map):
    table = bq_client.get_table(table_id)
    new_schema = []

    for field in table.schema:
        score = sensitivity_map.get(field.name)
        tag = get_policy_tag(field.name, score) if score else None

        updated_field = bigquery.SchemaField(
            name=field.name,
            field_type=field.field_type,
            mode=field.mode,
            description=field.description,
            policy_tags=bigquery.PolicyTagList([tag]) if tag else None
        )
        new_schema.append(updated_field)

    table.schema = new_schema
    bq_client.update_table(table, ["schema"])
    print("Policy tags successfully applied.")

# Entry point for Cloud Function
@functions_framework.cloud_event
def dlp_policy_tagger(cloud_event):
    try:
        # Decode message
        #pubsub_message = base64.b64decode(cloud_event.data["message"]["data"])
        #message_data = json.loads(pubsub_message)
        #print("Pub/Sub message:", message_data)

        bq_client = bigquery.Client()
        sensitivity_map = get_sensitivity_map(bq_client)
        apply_policy_tags(bq_client, TARGET_TABLE_ID, sensitivity_map)

    except Exception as e:
        print(" Failed to apply policy tags:", str(e))
        raise
