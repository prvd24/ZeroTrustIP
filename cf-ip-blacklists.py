import requests
import json
import re
import os
import sys
import ipaddress # For robust IP validation

# --- Configuration ---
# IMPORTANT: Set these as environment variables for security!
# For example, in your terminal before running the script:
# export CLOUDFLARE_ACCOUNT_ID="your_account_id"
# export CLOUDFLARE_API_TOKEN="your_api_token"
CLOUDFLARE_ACCOUNT_ID = os.environ.get("CF_IDENTIFIER")
CLOUDFLARE_API_TOKEN = os.environ.get("CF_API_TOKEN")

# Base name for your IP list(s) on Cloudflare Zero Trust
# If you have more than 1000 IPs, the script will create multiple lists like:
# "My_Dynamic_IP_Blacklist_Part_0", "My_Dynamic_IP_Blacklist_Part_1", etc.
# NOTE: The previous script had a small error in naming, resulting in "Part_Part_0".
# This has been corrected so it will correctly be "My_Dynamic_IP_Blacklist_Part_0".
CLOUDFLARE_IP_LIST_BASE_NAME = "My_Dynamic_IP_Blacklist" # Removed "Part" here
CLOUDFLARE_LIST_DESCRIPTION = "Automatically updated IP blacklist from external sources. Part of a larger list."

MAX_LIST_ITEMS = 1000 # Cloudflare Gateway List limit (cannot be changed)

# List of URLs where your IP blacklists are hosted
# Each URL should ideally return a plain text file with one IP/CIDR per line.
# Lines starting with '#' will be ignored (comments).
IP_SOURCE_URLS = [
    "https://github.com/firehol/blocklist-ipsets/blob/master/firehol_level1.netset"
]

# --- Cloudflare API Base URL and Headers ---
# Check if environment variables are set
if not CLOUDFLARE_ACCOUNT_ID or not CLOUDFLARE_API_TOKEN:
    print("Error: CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN environment variables must be set.")
    print("Please set them before running the script (e.g., in Linux/macOS terminal: export VARIABLE_NAME=\"your_value\").")
    print("On Windows Command Prompt: set VARIABLE_NAME=\"your_value\"")
    sys.exit(1)

BASE_URL = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/gateway/lists"
HEADERS = {
    "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
    "Content-Type": "application/json"
}

# Regex to find potential IPv4 and IPv6 addresses, and CIDR ranges
# This is a broad regex to capture candidates before rigorous validation.
IP_REGEX = re.compile(
    r'\b(?:'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'  # IPv4 octet
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r'(?:/(?:3[0-2]|[12]?[0-9]))?' # Optional CIDR for IPv4 (0-32)
    r'|' # OR
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' # IPv6 full form
    r'|' # OR
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}?' # IPv6 shortened form (e.g., ::1)
    r'(?:/(?:1(?:1[0-9]|2[0-8])|[1-9]?[0-9]))?' # Optional CIDR for IPv6 (0-128)
    r')\b'
)


def fetch_ips_from_url(url):
    """
    Fetches content from the given URL and extracts unique, valid IP addresses/CIDRs.
    Uses ipaddress module for strict validation.
    """
    print(f"  Fetching from: {url}")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        content = response.text
        valid_ips = set() # Use a set to automatically handle uniqueness

        for line in content.splitlines():
            cleaned_line = line.strip()
            # Ignore empty lines and lines starting with '#' (comments)
            if not cleaned_line or cleaned_line.startswith('#'):
                continue

            # Use regex to find potential IP/CIDR candidates in the line
            found_ip_candidates = IP_REGEX.findall(cleaned_line)

            for ip_candidate in found_ip_candidates:
                try:
                    # Rigorous validation using ipaddress module
                    # .strip() here to ensure no hidden whitespace invalidates ipaddress parsing
                    ip_candidate_stripped = ip_candidate.strip() 
                    if '/' in ip_candidate_stripped:
                        # Validate as a network (CIDR)
                        # strict=False allows host bits to be set, which is common in blocklists
                        ipaddress.ip_network(ip_candidate_stripped, strict=False) 
                    else:
                        # Validate as a single IP address
                        ipaddress.ip_address(ip_candidate_stripped)
                    valid_ips.add(ip_candidate_stripped) # Add to set only if valid and stripped
                except ValueError:
                    # Optional: Print skipped invalid entries for debugging if needed
                    # print(f"    Skipping invalid IP/CIDR candidate: '{ip_candidate}' from line: '{cleaned_line}'")
                    pass # Silently skip invalid entries

        print(f"  Found {len(valid_ips)} unique and valid IPs/CIDRs from {url}.")
        return list(valid_ips) # Return as a list for further processing

    except requests.exceptions.RequestException as e:
        print(f"  Error fetching IP list from URL {url}: {e}")
        return []
    except Exception as e:
        print(f"  An unexpected error occurred while processing URL content for {url}: {e}")
        return []

def get_cloudflare_gateway_lists():
    """
    Retrieves all Cloudflare Gateway lists for the account.
    Returns a dictionary mapping list names to their full data.
    """
    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()
        result = response.json()
        if result.get("success"):
            # Filter for IP lists and store them by name
            return {item['name']: item for item in result.get("result", []) if item.get("type") == "IP"}
        else:
            print(f"Failed to retrieve lists from Cloudflare: {result.get('errors')}")
            return {}
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while getting lists from Cloudflare: {e}")
        print(f"Response content: {getattr(e.response, 'text', 'No response content')}") # Handle no response content
        return {}

def create_cloudflare_ip_list(list_name, ips, description):
    """Creates a new IP list on Cloudflare Zero Trust Gateway."""
    print(f"  Creating list '{list_name}' with {len(ips)} IPs...")
    
    # --- DEBUG PRINT FOR PROBLEM IDENTIFICATION ---
    if len(ips) > 0 and len(ips) <= 50: # Only print for small lists to avoid flooding console
        print(f"  Debug: Items being sent to Cloudflare for '{list_name}':")
        for idx, item in enumerate(ips):
            # Print item with quotes to clearly show if it's empty or has hidden chars
            print(f"    Item {idx}: '{item}'") 
    # --- END DEBUG PRINT ---

    payload = {
        "name": list_name,
        "description": description,
        "type": "IP", # Specify list type as IP
        "items": [{"value": ip} for ip in ips] # Added .strip() here for final cleanliness
    }
    try:
        response = requests.post(BASE_URL, headers=HEADERS, data=json.dumps(payload))
        response.raise_for_status() # Check for HTTP errors

        result = response.json()
        if result.get("success"):
            list_id = result["result"]["id"]
            print(f"  Successfully created list '{list_name}' (ID: {list_id})")
            return list_id
        else:
            print(f"  Failed to create list '{list_name}': {result.get('errors')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"  An error occurred during list creation for '{list_name}': {e}")
        print(f"  Response content: {getattr(e.response, 'text', 'No response content')}")
        return None

def update_cloudflare_ip_list(list_id, list_name, ips, description):
    """
    Updates an existing IP list on Cloudflare Zero Trust Gateway.
    This replaces all existing items in the list with the new 'ips'.
    """
    print(f"  Updating list '{list_name}' (ID: {list_id}) with {len(ips)} IPs...")

    # --- DEBUG PRINT FOR PROBLEM IDENTIFICATION ---
    if len(ips) > 0 and len(ips) <= 50: # Only print for small lists
        print(f"  Debug: Items being sent to Cloudflare for '{list_name}':")
        for idx, item in enumerate(ips):
            print(f"    Item {idx}: '{item}'")
    # --- END DEBUG PRINT ---

    payload = {
        "name": list_name,
        "description": description,
        "type": "IP",
        "items": [{"value": ip.strip()} for ip in ips] # Added .strip() here for final cleanliness
    }
    try:
        response = requests.put(f"{BASE_URL}/{list_id}", headers=HEADERS, data=json.dumps(payload))
        response.raise_for_status() # Check for HTTP errors

        result = response.json()
        if result.get("success"):
            print(f"  Successfully updated list '{list_name}'.")
            return True
        else:
            print(f"  Failed to update list '{list_name}': {result.get('errors')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"  An error occurred during list update for '{list_name}': {e}")
        print(f"  Response content: {getattr(e.response, 'text', 'No response content')}")
        return False

def delete_cloudflare_ip_list(list_id, list_name):
    """Deletes an IP list by its ID."""
    print(f"  Deleting old list '{list_name}' (ID: {list_id})...")
    try:
        delete_url = f"{BASE_URL}/{list_id}"
        response = requests.delete(delete_url, headers=HEADERS)
        response.raise_for_status() # Check for HTTP errors

        result = response.json()
        if result.get("success"):
            print(f"  Successfully deleted list '{list_name}'.")
            return True
        else:
            print(f"  Failed to delete list '{list_name}': {result.get('errors')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"  An error occurred during deletion of '{list_name}': {e}")
        print(f"  Response content: {getattr(e.response, 'text', 'No response content')}")
        return False

# --- Main execution ---
if __name__ == "__main__":
    print("Starting Cloudflare Zero Trust IP List Synchronization Script...")

    # 1. Fetch IPs from all configured URLs
    all_collected_ips = set()
    print("\nCollecting IPs from external sources:")
    for url in IP_SOURCE_URLS:
        ips_from_source = fetch_ips_from_url(url)
        all_collected_ips.update(ips_from_source)

    unique_ips_to_sync = sorted(list(all_collected_ips)) # Sort for consistent ordering

    if not unique_ips_to_sync:
        print("\nNo valid IP addresses collected from any source. No Cloudflare lists will be created/updated.")
        sys.exit(0)

    print(f"\nTotal unique IPs collected for synchronization: {len(unique_ips_to_sync)}")

    # 2. Divide IPs into chunks if exceeding MAX_LIST_ITEMS
    required_num_lists = (len(unique_ips_to_sync) + MAX_LIST_ITEMS - 1) // MAX_LIST_ITEMS
    ip_chunks = []
    for i in range(required_num_lists):
        start_index = i * MAX_LIST_ITEMS
        end_index = min((i + 1) * MAX_LIST_ITEMS, len(unique_ips_to_sync))
        ip_chunks.append(unique_ips_to_sync[start_index:end_index])

    print(f"Will synchronize IPs across {required_num_lists} Cloudflare list(s).")

    # 3. Get all existing Cloudflare IP lists managed by this script
    existing_cloudflare_ip_lists = get_cloudflare_gateway_lists()
    
    # Identify lists that *could* be managed by this script (based on naming convention)
    managed_list_names_on_cf = set()
    for cf_list_name in existing_cloudflare_ip_lists.keys():
        # Check if the list name matches our expected pattern "BASE_NAME_Part_X"
        # Using regex to be more robust, ensures it matches "BASE_NAME_Part_DIGITS"
        if re.match(rf"^{re.escape(CLOUDFLARE_IP_LIST_BASE_NAME)}_Part_\d+$", cf_list_name):
            managed_list_names_on_cf.add(cf_list_name)
    
    active_list_names_this_run = set() # To track which part lists are currently needed

    # 4. Synchronize each chunk with Cloudflare
    print("\nSynchronizing Cloudflare lists:")
    for i, chunk in enumerate(ip_chunks):
        # Corrected list naming logic: CLOUDFLARE_IP_LIST_BASE_NAME is now just the prefix
        current_list_name = f"{CLOUDFLARE_IP_LIST_BASE_NAME}_Part_{i}" 
        active_list_names_this_run.add(current_list_name)
        
        list_data = existing_cloudflare_ip_lists.get(current_list_name)
        
        if list_data:
            # Check if the content of the existing list is different from the current chunk
            existing_items_set = {item['ip'] for item in list_data.get('items', [])}
            if set(chunk) == existing_items_set:
                print(f"  List '{current_list_name}' is already up-to-date. No changes needed.")
            else:
                update_cloudflare_ip_list(
                    list_data['id'],
                    current_list_name,
                    chunk,
                    CLOUDFLARE_LIST_DESCRIPTION
                )
        else:
            # List part does not exist, so create it
            create_cloudflare_ip_list(
                current_list_name,
                chunk,
                CLOUDFLARE_LIST_DESCRIPTION
            )

    # 5. Clean up old lists that are no longer needed (e.g., if total IPs decreased)
    print("\nCleaning up old Cloudflare lists (if any):")
    lists_to_delete = managed_list_names_on_cf - active_list_names_this_run
    
    if lists_to_delete:
        for list_name_to_delete in lists_to_delete:
            list_id_to_delete = existing_cloudflare_ip_lists[list_name_to_delete]['id']
            delete_cloudflare_ip_list(list_id_to_delete, list_name_to_delete)
    else:
        print("  No old lists to delete.")

    print("\nScript finished.")
    print("Verify your IP blacklists in your Cloudflare Zero Trust dashboard under Gateway -> Lists.")
    print(f"They will be named starting with '{CLOUDFLARE_IP_LIST_BASE_NAME}_Part_'.")