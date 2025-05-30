import requests
import time
import secrets
import string
import sys
import os

# === LOAD CONFIG FROM ENVIRONMENT VARIABLES ===
DA_API_URL = os.getenv("DA_API_URL", "https://your-mxroute-server:2222")
DA_USERNAME = os.getenv("DA_USERNAME")
DA_PASSWORD = os.getenv("DA_PASSWORD")
NAMESILO_API_KEY = os.getenv("NAMESILO_API_KEY")

if not DA_USERNAME or not DA_PASSWORD or not NAMESILO_API_KEY:
    print("ERROR: Please set DA_USERNAME, DA_PASSWORD, and NAMESILO_API_KEY environment variables.")
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
    return ''.join(secrets.choice(chars) for _ in range(length))

def da_api_post(endpoint, data):
    url = f"{DA_API_URL}{endpoint}"
    response = requests.post(url, data=data, auth=(DA_USERNAME, DA_PASSWORD), verify=False)
    response.raise_for_status()
    return response.text

def add_domain(domain):
    print(f"[+] Adding domain: {domain}")
    return da_api_post("/CMD_API_DOMAIN", {"action": "create", "domain": domain})

def get_dkim(domain):
    print("[+] Fetching DKIM key...")
    result = da_api_post("/CMD_API_EMAIL_DKIM", {"domain": domain})
    parsed = dict(line.split('=', 1) for line in result.split('&') if '=' in line)
    return parsed.get("publickey", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()

def namesilo_dns_add(domain, host, record_type, value, priority=""):
    print(f"[+] Adding DNS record to NameSilo: {host}.{domain} -> {record_type} {value}")
    url = f"https://www.namesilo.com/api/dnsAddRecord?version=1&type={record_type}&domain={domain}&rrhost={host}&rrvalue={value}&rrttl=7207&key={NAMESILO_API_KEY}"
    if record_type == "MX" and priority:
        url += f"&rrpriority={priority}"
    response = requests.get(url)
    response.raise_for_status()
    return response.text

def add_dns_records(domain, dkim_key):
    for host, record_type, value, priority in MX_RECORDS:
        namesilo_dns_add(domain, host, record_type, value, priority)
    # Add x._domainkey
    namesilo_dns_add(domain, "x._domainkey", "TXT", f'"v=DKIM1; k=rsa; p={dkim_key}"')

def request_ssl_cert(domain):
    print(f"[+] Requesting SSL cert via ACME for mail.{domain} and webmail.{domain}")
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
    print("[*] Checking if SSL cert is ready...")
    resp = da_api_post("/CMD_API_SSL", {"domain": domain})
    return "Certificate for" in resp and "mail." in resp and "webmail." in resp

def wait_for_cert(domain):
    print("[*] Waiting for SSL cert issuance...")
    for _ in range(20):  # wait max 10 mins
        if cert_ready(domain):
            print("[+] Certificate is ready!")
            return True
        time.sleep(30)
    print("[-] Certificate not ready after 10 mins.")
    return False

def create_email(domain, user, quota):
    # Convert quota string to MB integer
    quota_map = {
        "5GB": 5120,
        "10GB": 10240,
        "25GB": 25600
    }
    if quota not in quota_map:
        print("ERROR: Quota must be one of: 5GB, 10GB, 25GB")
        sys.exit(1)

    quota_mb = quota_map[quota]

    password = random_password()
    print(f"[+] Creating email account: {user}@{domain} with quota {quota}")
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
        print("Usage: python setup_mxroute_user.py <domain> <username> <quota>")
        print("Quota must be one of: 5GB, 10GB, 25GB")
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

    print("\n[✅] Setup Complete!")
    print(f"Email: {username}@{domain}")
    print(f"Password: {password}")


if __name__ == "__main__":
    main()
