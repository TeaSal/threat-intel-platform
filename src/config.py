"""
Central configuration: environment variables, file paths, and shared constants.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"

for d in (DATA_DIR, MODELS_DIR, REPORTS_DIR):
    d.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "threat_intel.db"

# --- API credentials ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # optional

# --- API endpoints ---
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# --- Collection parameters ---
NVD_RESULTS_PER_PAGE = 200          # NVD max page size
NVD_PAGES_TO_FETCH = 2              # keep small for a beginner project / rate limits
ABUSEIPDB_CONFIDENCE_MINIMUM = 50   # only pull IPs AbuseIPDB is at least 50% confident about
ABUSEIPDB_LIMIT = 500               # max IPs to request from the blacklist endpoint

# --- Source reliability weights (manually assigned, documented in the report) ---
# Used as a feature: reflects how much we trust each source's own scoring.
SOURCE_RELIABILITY = {
    "nvd": 0.9,          # NIST-maintained, authoritative for CVE severity
    "abuseipdb": 0.6,    # community-reported, more prone to false positives
}

# --- Priority label buckets (used by labeling.py) ---
PRIORITY_LABELS = ["Low", "Medium", "High", "Critical"]

RANDOM_SEED = 42
