from datetime import datetime, date, timezone
from pathlib import Path
import argparse
import pandas as pd
import logging
import json
import requests
import gzip
import os
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import the enrichment module
try:
    import enrich_nvd
except ImportError:
    logger.error("Could not import enrich module. Make sure enrich_nvd.py is in the same directory.")
    sys.exit(1)

# Constants
EPSS_CSV = f'https://epss.cyentia.com/epss_scores-current.csv.gz'
EPSS_BACKUP = './data/epss/epss_scores.csv'  # Backup location
TIMESTAMP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'last_run.txt')

# NVD REST API 2.0 base URL
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# NVD API rate limiting
# Without API key: ~10 req/min → 6 s between requests
# With API key:    ~50 req/min → 0.6 s between requests
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
NVD_SLEEP = 0.6 if NVD_API_KEY else 6.0
NVD_PAGE_SIZE = 2000  # Maximum allowed by the API


def create_directories():
    """Create necessary directories for the script"""
    os.makedirs('./data/epss', exist_ok=True)


# ---------------------------------------------------------------------------
# NVD API date formatting
# ---------------------------------------------------------------------------

def _nvd_date(dt: datetime) -> str:
    """
    Format a datetime for the NVD REST API.
    Required format: '2026-07-03T09:50:17.000 UTC+00:00'
    """
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000 UTC+00:00')


# ---------------------------------------------------------------------------
# Shared CVE parsing helpers (identical logic to the original feed parser)
# ---------------------------------------------------------------------------

def get_primary_metric(metrics_array):
    """
    Extract primary CVSS metric from array of metrics.

    Prefers metrics in this order:
    1. Type = 'Primary'
    2. Source = 'nvd@nist.gov'
    3. First entry in array

    Args:
        metrics_array (list): Array of CVSS metric objects

    Returns:
        dict: Selected metric object, or None if array is empty
    """
    if not metrics_array:
        return None

    # Prefer Primary type
    primary = [m for m in metrics_array if m.get('type') == 'Primary']
    if primary:
        return primary[0]

    # Prefer nvd@nist.gov source
    nvd_source = [m for m in metrics_array if 'nvd@nist.gov' in m.get('source', '')]
    if nvd_source:
        return nvd_source[0]

    # Fallback to first entry
    return metrics_array[0]


def extract_cvss_metrics(entry):
    """
    Extract CVSS metrics from JSON 2.0 entry with correct baseSeverity handling.

    🚨 CRITICAL: baseSeverity location differs by CVSS version!
    - CVSS v2: baseSeverity is at metric level (outside cvssData)
    - CVSS v3.0/3.1/4.0: baseSeverity is inside cvssData

    Args:
        entry (dict): The 'cve' object from JSON 2.0 vulnerability

    Returns:
        tuple: (version, baseScore, baseSeverity, vectorString)
               Returns ('N/A', 'N/A', 'N/A', 'N/A') if no CVSS data found
    """
    metrics = entry.get('metrics', {})

    # Try CVSS 4.0 first (newest)
    if 'cvssMetricV40' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV40'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '4.0',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v4.0
                cvss_data.get('vectorString', 'N/A')
            )

    # Try CVSS 3.1
    elif 'cvssMetricV31' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV31'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '3.1',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v3.1
                cvss_data.get('vectorString', 'N/A')
            )

    # Try CVSS 3.0
    elif 'cvssMetricV30' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV30'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '3.0',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v3.0
                cvss_data.get('vectorString', 'N/A')
            )

    # Try CVSS 2.0 (legacy)
    elif 'cvssMetricV2' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV2'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '2.0',
                cvss_data.get('baseScore', 'N/A'),
                metric.get('baseSeverity', 'N/A'),  # ⚠️ OUTSIDE cvssData for v2!
                cvss_data.get('vectorString', 'N/A')
            )

    # No CVSS data found
    return ('N/A', 'N/A', 'N/A', 'N/A')


def _parse_cve_entry(vuln_item: dict) -> dict | None:
    """
    Parse a single vulnerability item from the NVD API response into a flat dict.
    Returns None if the entry should be skipped (Rejected / Reserved).
    """
    entry = vuln_item.get('cve', {})

    vuln_status = entry.get('vulnStatus', '')
    if vuln_status in ['Rejected', 'Reserved']:
        return None

    cve = entry.get('id', 'N/A')
    cvss_version, base_score, base_severity, base_vector = extract_cvss_metrics(entry)
    assigner = entry.get('sourceIdentifier', 'N/A')
    published_date = entry.get('published', '')
    last_modified_date = entry.get('lastModified', '')

    descriptions = entry.get('descriptions', [])
    description = next(
        (d.get('value', 'N/A') for d in descriptions if d.get('lang') == 'en'),
        'N/A'
    )

    return {
        'cve': cve,
        'cvss_version': cvss_version,
        'base_score': base_score,
        'base_severity': base_severity,
        'base_vector': base_vector,
        'assigner': assigner,
        'published_date': published_date,
        'last_modified_date': last_modified_date,
        'description': description,
    }


# ---------------------------------------------------------------------------
# Incremental fetch via NVD REST API
# ---------------------------------------------------------------------------

def fetch_nvd_incremental(since: str) -> pd.DataFrame:
    """
    Fetch only CVEs that were created or modified since *since* using the
    NVD REST API 2.0.

    Args:
        since (str): ISO-8601 UTC timestamp of the last successful run,
                     e.g. '2026-07-03T09:50:17Z'

    Returns:
        pandas.DataFrame: CVEs modified/added since *since*.
    """
    # Parse the stored timestamp and compute now
    since_dt = datetime.strptime(since.rstrip('Z'), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    now_dt = datetime.now(timezone.utc)

    params = {
        'lastModStartDate': _nvd_date(since_dt),
        'lastModEndDate': _nvd_date(now_dt),
        'resultsPerPage': NVD_PAGE_SIZE,
        'startIndex': 0,
    }
    if NVD_API_KEY:
        params['apiKey'] = NVD_API_KEY

    headers = {'User-Agent': 'cvss-te-updater/1.0'}

    logger.info(f"Fetching incremental NVD data from {params['lastModStartDate']} to {params['lastModEndDate']}")

    all_records: list[dict] = []
    page = 0

    while True:
        params['startIndex'] = page * NVD_PAGE_SIZE

        for attempt in range(3):
            try:
                response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=60)
                response.raise_for_status()
                data = response.json()
                break
            except requests.exceptions.RequestException as e:
                logger.warning(f"NVD API request failed (attempt {attempt + 1}/3): {e}")
                if attempt < 2:
                    time.sleep(10)
                else:
                    logger.error("NVD API request failed after 3 attempts – aborting incremental fetch")
                    raise

        total_results = data.get('totalResults', 0)
        results_per_page = data.get('resultsPerPage', NVD_PAGE_SIZE)
        vulnerabilities = data.get('vulnerabilities', [])

        if page == 0:
            logger.info(f"NVD API: {total_results} CVEs modified since last run")

        for vuln_item in vulnerabilities:
            record = _parse_cve_entry(vuln_item)
            if record:
                all_records.append(record)

        fetched_so_far = params['startIndex'] + results_per_page
        if fetched_so_far >= total_results or not vulnerabilities:
            break

        page += 1
        logger.info(f"Fetching page {page + 1} (startIndex={params['startIndex'] + NVD_PAGE_SIZE}, total={total_results})")
        time.sleep(NVD_SLEEP)

    if not all_records:
        logger.info("No new or modified CVEs found since last run")
        return pd.DataFrame()

    df = pd.DataFrame(all_records)
    logger.info(f"Incremental fetch complete: {df['cve'].nunique()} unique CVEs")
    return df


# ---------------------------------------------------------------------------
# Full rebuild via legacy year feeds (used with --full flag)
# ---------------------------------------------------------------------------

def generate_nvd_feeds():
    """Generate a dictionary of all NVD feeds from 2002 to present year"""
    feeds = {
        'recent': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz',
        'modified': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz',
    }

    current_year = date.today().year
    for year in range(2002, current_year + 1):
        feeds[str(year)] = f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz'

    return feeds


NVD_FEEDS = generate_nvd_feeds()


def download_nvd_feeds(max_retries=3, retry_delay=5):
    """
    Download NVD feeds, decompress them, and save to the current directory.
    Used only during a full rebuild (--full flag).

    Returns:
        list: List of downloaded JSON filenames.
    """
    downloaded_files = []

    for feed_name, feed_url in NVD_FEEDS.items():
        output_path = f"nvdcve-2.0-{feed_name}.json"

        # Skip downloading if file exists and is less than 1 day old (except for recent/modified)
        if os.path.exists(output_path) and feed_name not in ['recent', 'modified']:
            file_age = time.time() - os.path.getmtime(output_path)
            file_size = os.path.getsize(output_path)
            if file_size > 0 and file_age < 86400:
                logger.info(f"Using existing file for {feed_name} feed: {output_path} ({file_size} bytes)")
                downloaded_files.append(output_path)
                continue

        for attempt in range(max_retries):
            try:
                logger.info(f"Downloading NVD feed: {feed_name} from {feed_url} (attempt {attempt+1}/{max_retries})")
                response = requests.get(feed_url, stream=True, timeout=120)
                response.raise_for_status()

                logger.info(f"Decompressing {feed_name} feed")
                json_data = gzip.decompress(response.content)
                json.loads(json_data)  # validate JSON

                logger.info(f"Saving {feed_name} feed to {output_path}")
                with open(output_path, 'wb') as f:
                    f.write(json_data)

                file_size = os.path.getsize(output_path)
                logger.info(f"Saved {output_path}: {file_size} bytes")
                downloaded_files.append(output_path)

                # Add delay between downloads (except for last item)
                if feed_name not in ['recent', 'modified']:
                    time.sleep(1)

                break

            except requests.exceptions.RequestException as e:
                logger.warning(f"Error downloading {feed_name} feed (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Failed to download {feed_name} feed after {max_retries} attempts")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {feed_name} feed: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error processing {feed_name} feed: {e}")
                break

    return downloaded_files


def process_nvd_files() -> pd.DataFrame:
    """
    Processes the NVD JSON files downloaded by download_nvd_feeds().
    Used only during a full rebuild (--full flag).

    Returns:
        pandas.DataFrame: DataFrame with extracted NVD data.
    """
    nvd_dict = []
    json_files = list(Path('.').glob('nvdcve-2.0-*.json'))

    if not json_files:
        logger.warning("No NVD JSON files found in the current directory")
        return pd.DataFrame()

    for file_path in json_files:
        logger.info(f'Processing {file_path.name}')
        try:
            with file_path.open('r', encoding='utf-8') as file:
                data = json.load(file)
                vulnerabilities = data.get('vulnerabilities', [])
                logger.info(f'CVEs in {file_path.name}: {len(vulnerabilities)}')

                for vuln_item in vulnerabilities:
                    try:
                        record = _parse_cve_entry(vuln_item)
                        if record:
                            nvd_dict.append(record)
                    except Exception as e:
                        cve_id = vuln_item.get('cve', {}).get('id', 'Unknown')
                        logger.warning(f"Error processing entry in {file_path.name} for CVE {cve_id}: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error processing file {file_path.name}: {e}")
            continue

    if not nvd_dict:
        logger.warning("No CVE data extracted from JSON files")
        return pd.DataFrame()

    nvd_df = pd.DataFrame(nvd_dict)

    if not nvd_df.empty and 'cvss_version' in nvd_df.columns:
        version_counts = nvd_df['cvss_version'].value_counts()
        logger.info(f'CVSS version distribution: {version_counts.to_dict()}')

    logger.info(f'Total CVEs extracted from NVD: {nvd_df["cve"].nunique()}')
    return nvd_df


def fetch_nvd_full() -> pd.DataFrame:
    """Full rebuild: download all year feeds and parse them."""
    logger.info("Starting full NVD download (all year feeds)")
    download_nvd_feeds()
    df = process_nvd_files()

    # Clean up temporary JSON files
    logger.info("Cleaning up temporary NVD JSON files...")
    for f in Path('.').glob('nvdcve-2.0-*.json'):
        try:
            f.unlink()
        except OSError as e:
            logger.warning(f"Could not remove {f}: {e}")
    logger.info("Cleanup complete")

    return df


# ---------------------------------------------------------------------------
# Upsert helper
# ---------------------------------------------------------------------------

def upsert_csv(new_df: pd.DataFrame, output_path: str) -> pd.DataFrame:
    """
    Merge *new_df* (new/updated CVE base data, not yet enriched) into the
    existing *output_path* CSV.

    Strategy:
    - Load existing enriched CSV.
    - For CVEs present in *new_df*, replace all columns with the freshly
      fetched NVD values (enrichment will re-run for these rows).
    - For CVEs NOT in *new_df*, keep the existing rows exactly as-is.
    - Return the merged DataFrame sorted by published_date.

    Args:
        new_df:      DataFrame of newly fetched CVE base rows.
        output_path: Path to the existing cvss-te.csv.

    Returns:
        pandas.DataFrame: Merged DataFrame ready for enrichment of new_df rows.
    """
    if not os.path.exists(output_path):
        logger.info("No existing CSV found – treating as full build")
        return new_df

    try:
        existing_df = pd.read_csv(output_path, low_memory=False)
        logger.info(f"Loaded existing CSV: {len(existing_df)} rows")
    except Exception as e:
        logger.warning(f"Could not read existing CSV ({e}) – treating as full build")
        return new_df

    new_cves = set(new_df['cve'].tolist())
    kept_df = existing_df[~existing_df['cve'].isin(new_cves)].copy()

    logger.info(
        f"Upsert: {len(new_cves)} CVEs to re-enrich "
        f"({len(new_cves) - len(existing_df[existing_df['cve'].isin(new_cves)])} new, "
        f"{len(existing_df[existing_df['cve'].isin(new_cves)])} updated), "
        f"{len(kept_df)} unchanged rows carried forward"
    )

    return new_df, kept_df


# ---------------------------------------------------------------------------
# EPSS download (always fresh)
# ---------------------------------------------------------------------------

def download_epss_data(url, backup_path=None):
    """
    Downloads the EPSS data from the URL and returns a DataFrame.
    If the download fails, tries to use the backup file if available.

    Returns:
        pandas.DataFrame: DataFrame containing EPSS data.
    """
    try:
        logger.info(f"Downloading EPSS data from {url}")
        epss_df = pd.read_csv(url, comment='#', compression='gzip')
        if backup_path:
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            epss_df.to_csv(backup_path, index=False)
            logger.info(f"Saved EPSS backup to {backup_path}")

        return epss_df
    except Exception as e:
        logger.warning(f"Failed to download EPSS data: {e}")
        if backup_path and os.path.exists(backup_path):
            logger.info(f"Using backup EPSS data from {backup_path}")
            return pd.read_csv(backup_path)
        else:
            logger.error("No backup EPSS data available")
            raise


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich_df(nvd_df):
    """
    Enriches the dataframe with exploit maturity and temporal scores.

    Args:
        nvd_df (pandas.DataFrame): DataFrame containing NVD data.

    Returns:
        pandas.DataFrame: Enriched DataFrame with temporal scores.
    """
    if nvd_df.empty:
        logger.warning("No NVD data to enrich")
        return pd.DataFrame()

    logger.info('Loading EPSS data')
    try:
        epss_df = download_epss_data(EPSS_CSV, EPSS_BACKUP)
    except Exception as e:
        logger.error(f"Failed to load EPSS data: {e}")
        return nvd_df

    logger.info('Enriching data with exploit information')
    try:
        enriched_df = enrich_nvd.enrich(nvd_df, epss_df)
    except Exception as e:
        logger.error(f"Error during enrichment: {e}")
        return nvd_df

    logger.info('Updating temporal scores based on exploit maturity')
    try:
        cvss_te_df = enrich_nvd.update_temporal_score(enriched_df, enrich_nvd.EPSS_THRESHOLD)
    except Exception as e:
        logger.error(f"Error updating temporal scores: {e}")
        return enriched_df

    # Define the essential columns with both BT and TE data
    essential_columns = [
        'cve',
        'cvss_version',
        'base_score',
        'base_severity',
        'base_vector',
        'assigner',
        'published_date',
        'last_modified_date',
        'epss',
        'cisa_kev',
        'vulncheck_kev',
        'exploitdb',
        'metasploit',
        'nuclei',
        'poc_github',
        'reliability',
        'ease_of_use',
        'effectiveness',
        'quality_score',
        'exploit_sources',
        'exploit_maturity',
        # BT score (standard temporal)
        'cvss-bt_score',
        'cvss-bt_severity',
        'cvss-bt_vector',
        # TE score (enhanced)
        'cvss-te_score',
        'cvss-te_severity'
    ]

    available_columns = [col for col in essential_columns if col in cvss_te_df.columns]
    cvss_te_df = cvss_te_df[available_columns]

    # Flatten multi-line text in description fields
    def flatten_text(x):
        if isinstance(x, str):
            return x.replace('\n', ' ').replace('\r', ' ')
        return x
    cvss_te_df = cvss_te_df.applymap(flatten_text)

    # Convert boolean columns to integers
    bool_columns = ['cisa_kev', 'vulncheck_kev', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']
    for col in bool_columns:
        if col in cvss_te_df.columns:
            cvss_te_df[col] = cvss_te_df[col].astype(int)

    return cvss_te_df


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def load_last_run_timestamp(filename=TIMESTAMP_FILE) -> str | None:
    """Return the stored timestamp string, or None if not available."""
    try:
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                ts = f.read().strip()
                if ts:
                    return ts
    except Exception as e:
        logger.warning(f"Could not read timestamp file: {e}")
    return None


def save_last_run_timestamp(filename=TIMESTAMP_FILE):
    """
    Save the current timestamp as the last run timestamp in a file.
    Uses proper UTC time to match the 'Z' suffix in the ISO 8601 format.
    """
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            utc_now = datetime.now(timezone.utc)
            timestamp = utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')
            f.write(timestamp)
        logger.info(f"Timestamp saved: {timestamp}")
    except Exception as e:
        logger.error(f"Error saving timestamp to {filename}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='NVD CVE processing and enrichment pipeline')
    parser.add_argument(
        '--full',
        action='store_true',
        help='Force a full rebuild by downloading all NVD year feeds (slow). '
             'Default is incremental (only new/modified CVEs since last run).'
    )
    args = parser.parse_args()

    logger.info("Starting NVD processing and enrichment pipeline")

    output_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'cvss-te.csv'
    )

    try:
        create_directories()

        # ------------------------------------------------------------------
        # Decide: full rebuild or incremental?
        # ------------------------------------------------------------------
        full_mode = args.full
        if not full_mode:
            last_run = load_last_run_timestamp()
            if not last_run:
                logger.warning("No last_run.txt found – falling back to full rebuild")
                full_mode = True

        # ------------------------------------------------------------------
        # FULL REBUILD
        # ------------------------------------------------------------------
        if full_mode:
            logger.info("=== FULL REBUILD MODE ===")
            nvd_df = fetch_nvd_full()
            if nvd_df.empty:
                logger.warning("No NVD data to process. Exiting.")
                return

            logger.info(f"Total unique CVEs to process: {nvd_df['cve'].nunique()}")
            enriched_df = enrich_df(nvd_df)
            if enriched_df.empty:
                logger.warning("Enrichment resulted in empty dataset. Check for errors.")
                return

            fixed_df = enrich_nvd.recalculate_problem_cves(enriched_df)
            fixed_df = fixed_df.sort_values(by=['published_date']).reset_index(drop=True)
            logger.info(f'Saving full dataset to {output_file} ({len(fixed_df)} rows)')
            fixed_df.to_csv(output_file, index=False, mode='w')

        # ------------------------------------------------------------------
        # INCREMENTAL UPDATE
        # ------------------------------------------------------------------
        else:
            logger.info(f"=== INCREMENTAL MODE (changes since {last_run}) ===")
            new_df = fetch_nvd_incremental(last_run)

            if new_df.empty:
                logger.info("No CVE changes detected – nothing to update.")
                save_last_run_timestamp(TIMESTAMP_FILE)
                return

            # Split: rows to re-enrich vs rows to keep as-is
            new_base_df, kept_df = upsert_csv(new_df, output_file)

            logger.info(f"Re-enriching {new_base_df['cve'].nunique()} changed CVEs")
            enriched_new = enrich_df(new_base_df)
            if enriched_new.empty:
                logger.warning("Enrichment of changed CVEs returned empty result – skipping update.")
                return

            fixed_new = enrich_nvd.recalculate_problem_cves(enriched_new)

            # Merge enriched new rows back with unchanged rows
            combined_df = pd.concat([kept_df, fixed_new], ignore_index=True)

            # Align columns: fill any missing columns from kept_df with NaN
            combined_df = combined_df.sort_values(by=['published_date']).reset_index(drop=True)

            logger.info(f'Saving merged dataset to {output_file} ({len(combined_df)} rows total)')
            combined_df.to_csv(output_file, index=False, mode='w')

        save_last_run_timestamp(TIMESTAMP_FILE)
        logger.info("NVD processing and enrichment pipeline completed successfully")

    except Exception as e:
        logger.error(f"Unhandled exception in main process: {e}")
        raise


if __name__ == "__main__":
    main()
