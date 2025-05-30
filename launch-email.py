import requests
import time
import secrets
import string
import sys
import os
import logging
from dotenv import load_dotenv
load_dotenv()
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === SETUP LOGGING ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger()

# === LOAD CONFIG FROM ENVIRONMENT VARIABLES ===
DA_API_URL = os.getenv("DA_API_URL")
DA_USERNAME = os.getenv("DA_USERNAME")
DA_PASSWORD = os.getenv("DA_PASSWORD")
NAMESILO_API_KEY = os.getenv("NAMESILO_API_KEY")

if not DA_USERNAME or not DA_PASSWORD or not NAMESILO_API_KEY:
    logger.error("Please set DA_USERNAME, DA_PASSWORD, and NAMESILO_API_KEY environment variables.")
    sys.exit(1)


MX_RECORDS = [
    ("@", "MX", "heracles.mxrouting.net", "10"),
    ("@", "MX", "heracles-relay.mxrouting.net", "20"),
    ("@", "TXT", '"v=spf1 include:mxlogin.com -all"', ""),
    ("mail", "CNAME", "heracles.mxrouting.net", ""),
    ("webmail", "CNAME", "heracles.mxrouting.net", "")
]

# === UTILITY FUNCTIONS ===

def random_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%&"
    pwd = ''.join(secrets.choice(chars) for _ in range(length))
    logger.debug(f"Generated random password: {pwd}")
    return pwd

def da_api_post(endpoint, data):
    url = f"{DA_API_URL}{endpoint}"
    logger.info(f"POST to {url} with data: {data}")
    try:
        response = requests.post(url, data=data, auth=(DA_USERNAME, DA_PASSWORD), verify=False)
        response.raise_for_status()
        logger.debug(f"Response: {response.text}")
        return response.text
    except requests.RequestException as e:
        logger.error(f"API POST request failed: {e}")
        sys.exit(1)

def add_domain(domain):
    logger.info(f"Adding domain: {domain}")
    return da_api_post("/CMD_API_DOMAIN", {"action": "create", "domain": domain})

def get_dkim(domain):
    logger.info(f"Fetching DKIM key for domain {domain}...")
    endpoint = "/CMD_DNS_CONTROL"
    params = {
        "json": "yes",
        "domain": domain,
        "ttl": "yes"
    }
    url = f"{DA_API_URL}{endpoint}"
    try:
        response = requests.get(url, params=params, auth=(DA_USERNAME, DA_PASSWORD), verify=False)
        response.raise_for_status()
        data = response.json()

        # Look for TXT record with name == "x._domainkey"
        for record in data.get("records", []):
            if record.get("type") == "TXT" and record.get("name") == "x._domainkey":
                dkim_value = record.get("value", "")
                # The value might be quoted, remove quotes if any
                dkim_key = dkim_value.strip('"')
                logger.info(f"Found DKIM key: {dkim_key[:30]}...")  # log first 30 chars
                return dkim_key
        
        logger.error("DKIM TXT record not found in DNS records.")
        return ""

    except requests.RequestException as e:
        logger.error(f"Failed to fetch DKIM key: {e}")
        sys.exit(1)

def namesilo_dns_add(domain, host, record_type, value, priority=""):
    logger.info(f"Adding DNS record to NameSilo: {host}.{domain} -> {record_type} {value}")
    url = f"https://www.namesilo.com/api/dnsAddRecord?version=1&type=json&rrtype={record_type}&domain={domain}&rrvalue={value}&rrttl=7207&key={NAMESILO_API_KEY}"

    # Conditionally add rrhost if it's not the root domain ("@")
    if host and host != "@":
        url += f"&rrhost={host}"

    if record_type == "MX":
        if not priority:
            logger.warning("MX record type requires a priority. 'priority' parameter is empty. Sending with empty priority.")
        url += f"&rrpriority={priority}"
    elif record_type == "SRV" and priority: # SRV also uses priority but it's optional
        url += f"&rrpriority={priority}"

    logger.debug(f"NameSilo DNS add URL: {url}") # Log the full URL being sent

    try:
        response = requests.get(url)
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        response_json = response.json() # Parse the JSON response
        logger.debug(f"NameSilo response (JSON): {response_json}")
        
        reply_data = response_json.get('namesilo', {}).get('reply', {})
        reply_code = reply_data.get('code')
        reply_detail = reply_data.get('detail')

        if reply_code == '300': # NameSilo's success code
            logger.info(f"Successfully added DNS record: {host}.{domain} -> {record_type} {value}")
        else:
            logger.error(f"NameSilo DNS add failed with code {reply_code}: {reply_detail}")
            sys.exit(1) # Exiting on non-success API response

        return response_json
    except requests.RequestException as e:
        logger.error(f"Network request to NameSilo DNS add failed: {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse NameSilo JSON response: {e}")
        logger.error(f"Raw response text: {response.text}") # Log raw text for debugging
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors during processing
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

# Your existing add_dns_records function:
def add_dns_records(domain, dkim_key):
    for host, record_type, value, priority in MX_RECORDS:
        namesilo_dns_add(domain, host, record_type, value, priority)
    # Add x._domainkey
    namesilo_dns_add(domain, "x._domainkey", "TXT", f'"v=DKIM1; k=rsa; p={dkim_key}"')


def request_ssl_cert(domain):
    logger.info(f"Requesting SSL cert via ACME for mail.{domain} and webmail.{domain}")
    return da_api_post("/CMD_SSL", {
        "acme_provider": "letsencrypt",
        "action": "save",
        "background": "auto",
        "domain": domain,
        "encryption": "sha256",
        "json": "yes",
        "keysize": "secp384r1",
        "le_select0": f"mail.{domain}",
        "le_select1": f"webmail.{domain}",
        "name": f"mail.{domain}",
        "request": "letsencrypt",
        "type": "create",
        "wildcard": "no"
    })

def cert_ready(domain):
    logger.info("Checking if SSL cert is ready...")
    resp = da_api_post("/CMD_API_SSL", {"domain": domain})
    ready = "Certificate for" in resp and "mail." in resp and "webmail." in resp
    logger.debug(f"Certificate ready: {ready}")
    return ready

def wait_for_cert(domain):
    logger.info("Waiting for SSL cert issuance...")
    for _ in range(20):  # wait max 10 mins
        if cert_ready(domain):
            logger.info("Certificate is ready!")
            return True
        time.sleep(30)
    logger.warning("Certificate not ready after 10 mins.")
    return False

def create_email(domain, user, quota):
    quota_map = {
        "5GB": 5120,
        "10GB": 10240,
        "25GB": 25600
    }
    if quota not in quota_map:
        logger.error("Quota must be one of: 5GB, 10GB, 25GB")
        sys.exit(1)

    quota_mb = quota_map[quota]

    password = random_password()
    logger.info(f"Creating email account: {user}@{domain} with quota {quota}")
    da_api_post("/CMD_API_POP", {
        "action": "create",
        "domain": domain,
        "user": user,
        "passwd": password,
        "passwd2": password,
        "quota": str(quota_mb)
    })
    return password


# === MAIN SCRIPT ===
def main():
    if len(sys.argv) != 4:
        logger.error("Usage: python setup_mxroute_user.py <domain> <username> <quota>")
        logger.error("Quota must be one of: 5GB, 10GB, 25GB")
        sys.exit(1)

    domain = sys.argv[1]
    username = sys.argv[2]
    quota = sys.argv[3]

    add_domain(domain)
    dkim = get_dkim(domain)
    add_dns_records(domain, dkim)
    request_ssl_cert(domain)
    wait_for_cert(domain)
    password = create_email(domain, username, quota)

    logger.info("\n[✅] Setup Complete!")
    logger.info(f"Email: {username}@{domain}")
    logger.info(f"Password: {password}")


if __name__ == "__main__":
    main()
