#!/usr/bin/env python3
"""
Azure Cost Details Extractor - Streaming V4

Purpose
-------
Extract monthly Azure Cost Details as ActualCost, AmortizedCost, or both.
V4 supports interactive metric selection (Actual, Amortized, or Both), while retaining --metric for automation. It also reports elapsed time for every monthly file, each month, and the full run.

The Motiva billing-account scope is embedded below. The extractor:
- calls Azure Cost Management generateCostDetailsReport
- polls asynchronous report generation
- streams report blobs to monthly CSV files
- writes to .part and renames only after successful completion
- reuses non-empty completed CSV files unless --no-cache is specified
- reads token expiration from the JWT exp claim
- refreshes tokens proactively and retries once after HTTP 401
- honors Retry-After and retries HTTP 429 and transient 5xx responses

Requirements
------------
- Azure CLI authenticated with access to the billing-account scope
- Python 3.9+
- requests: python -m pip install requests
"""

import argparse
import base64
import calendar
import json
import os
import random
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests

SCOPE = "/providers/Microsoft.Billing/billingAccounts/7f0b5ed1-81ed-4ca8-9fbf-4c10d9fa3b6e:baf7f5a2-b1d9-4bd5-9d0b-2ff03def9d79_2019-05-31"
API_VERSION = "2026-06-01"
ARM_RESOURCE = "https://management.azure.com/"
GENERATE_URL = (
    f"https://management.azure.com{SCOPE}"
    f"/providers/Microsoft.CostManagement/generateCostDetailsReport"
    f"?api-version={API_VERSION}"
)
USER_AGENT = "Motiva-Azure-Cost-Details-Extractor-V4/1.0"


def mib(value: int) -> float:
    return value / (1024 * 1024)


def parse_iso_date(value: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid date '{value}'; use YYYY-MM-DD") from exc


def month_windows(start: date, end: date) -> Iterable[Tuple[date, date]]:
    cursor = date(start.year, start.month, 1)
    while cursor <= end:
        month_last = date(cursor.year, cursor.month, calendar.monthrange(cursor.year, cursor.month)[1])
        yield max(start, cursor), min(end, month_last)
        cursor = date(cursor.year + (cursor.month == 12), 1 if cursor.month == 12 else cursor.month + 1, 1)


def jwt_exp_utc(token: str) -> datetime:
    parts = token.split(".")
    if len(parts) < 2:
        raise RuntimeError("Azure CLI returned a token that is not a JWT.")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    if "exp" not in data:
        raise RuntimeError("Azure access token does not contain an exp claim.")
    return datetime.fromtimestamp(int(data["exp"]), tz=timezone.utc)


class AzureTokenProvider:
    def __init__(self, refresh_margin_seconds: int = 300):
        self.refresh_margin = timedelta(seconds=refresh_margin_seconds)
        self.token: Optional[str] = None
        self.expires_utc: datetime = datetime.min.replace(tzinfo=timezone.utc)

    def invalidate(self) -> None:
        self.token = None
        self.expires_utc = datetime.min.replace(tzinfo=timezone.utc)

    def get(self, force: bool = False) -> str:
        now = datetime.now(timezone.utc)
        if not force and self.token and now + self.refresh_margin < self.expires_utc:
            return self.token

        cmd = [
            "az", "account", "get-access-token",
            "--resource", ARM_RESOURCE,
            "--query", "accessToken",
            "-o", "tsv",
        ]
        try:
            completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("Azure CLI 'az' was not found.") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise RuntimeError(f"Azure CLI token acquisition failed: {detail}") from exc

        token = completed.stdout.strip()
        if not token:
            raise RuntimeError("Azure CLI returned an empty access token.")
        self.token = token
        self.expires_utc = jwt_exp_utc(token)
        minutes = max(0, int((self.expires_utc - now).total_seconds() // 60))
        print(f"[AUTH] Azure access token acquired/refreshed; valid for about {minutes} minutes.", flush=True)
        return token


class AzureHttp:
    def __init__(self, token_provider: AzureTokenProvider, timeout: int = 120):
        self.tokens = token_provider
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    @staticmethod
    def retry_delay(response: requests.Response, attempt: int) -> float:
        raw = response.headers.get("Retry-After", "").strip()
        if raw.isdigit():
            return max(1.0, float(raw))
        return min(300.0, (2 ** min(attempt, 7)) + random.uniform(0.0, 2.0))

    def request(self, method: str, url: str, *, max_attempts: int = 12, **kwargs) -> requests.Response:
        refreshed_after_401 = False
        for attempt in range(1, max_attempts + 1):
            headers = dict(kwargs.pop("headers", {}) or {})
            headers["Authorization"] = f"Bearer {self.tokens.get()}"
            headers.setdefault("Accept", "application/json")
            try:
                response = self.session.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                if attempt == max_attempts:
                    raise RuntimeError(f"Network failure calling {url}: {exc}") from exc
                delay = min(120.0, 2 ** min(attempt, 6))
                print(f"[RETRY] Network error; retrying in {delay:.0f} seconds ...", flush=True)
                time.sleep(delay)
                continue

            if response.status_code == 401 and not refreshed_after_401:
                self.tokens.invalidate()
                self.tokens.get(force=True)
                refreshed_after_401 = True
                continue

            if response.status_code == 429 or 500 <= response.status_code <= 599:
                if attempt == max_attempts:
                    raise RuntimeError(
                        f"HTTP {response.status_code} calling {url}\n{response.text[:2000]}"
                    )
                delay = self.retry_delay(response, attempt)
                print(
                    f"[RETRY] HTTP {response.status_code}; waiting {delay:.0f} seconds "
                    f"(attempt {attempt}/{max_attempts}) ...",
                    flush=True,
                )
                time.sleep(delay)
                continue

            if not response.ok:
                raise RuntimeError(f"HTTP {response.status_code} calling {url}\n{response.text[:4000]}")
            return response

        raise RuntimeError(f"Request attempts exhausted for {url}")


def parse_json(response: requests.Response, context: str) -> Dict:
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{context} returned invalid JSON: {response.text[:2000]}") from exc


def create_report(http: AzureHttp, metric: str, start: date, end: date) -> Tuple[str, Optional[int]]:
    body = {
        "metric": metric,
        "timePeriod": {
            "start": f"{start.isoformat()}T00:00:00Z",
            "end": f"{end.isoformat()}T23:59:59Z",
        },
    }
    response = http.request("POST", GENERATE_URL, json=body)

    # Most successful calls return 202 + Location. Handle an immediate manifest too.
    if response.status_code == 200:
        data = parse_json(response, "Report generation")
        return json.dumps(data), 0

    location = response.headers.get("Location") or response.headers.get("location")
    if not location:
        data = parse_json(response, "Report generation")
        location = data.get("location") or data.get("properties", {}).get("location")
    if not location:
        raise RuntimeError("Azure accepted the report request but returned no polling Location.")

    retry_after_raw = response.headers.get("Retry-After", "")
    retry_after = int(retry_after_raw) if retry_after_raw.isdigit() else None
    return location, retry_after


def poll_manifest(http: AzureHttp, location_or_json: str, initial_wait: Optional[int]) -> Dict:
    if location_or_json.startswith("{"):
        return json.loads(location_or_json)

    if initial_wait:
        time.sleep(max(1, initial_wait))

    deadline = time.monotonic() + 60 * 60
    poll_count = 0
    while time.monotonic() < deadline:
        poll_count += 1
        response = http.request("GET", location_or_json)
        data = parse_json(response, "Report status")
        status = str(data.get("status") or data.get("properties", {}).get("status") or "").lower()

        manifest = data.get("manifest") or data.get("properties", {}).get("manifest")
        if manifest:
            return data
        if status in {"completed", "succeeded", "success"}:
            return data
        if status in {"failed", "failure", "cancelled", "canceled"}:
            raise RuntimeError(f"Azure cost-detail report failed: {json.dumps(data)[:4000]}")

        retry_raw = response.headers.get("Retry-After", "")
        delay = int(retry_raw) if retry_raw.isdigit() else min(30, 5 + poll_count)
        time.sleep(max(1, delay))

    raise RuntimeError("Timed out after 60 minutes waiting for the Azure cost-detail report.")


def get_blob_links(report: Dict) -> List[str]:
    manifest = report.get("manifest") or report.get("properties", {}).get("manifest") or report
    blobs = manifest.get("blobs") or manifest.get("blobLinks") or []
    links: List[str] = []
    for blob in blobs:
        if isinstance(blob, str):
            links.append(blob)
        elif isinstance(blob, dict):
            link = blob.get("blobLink") or blob.get("link") or blob.get("url")
            if link:
                links.append(link)
    if not links:
        raise RuntimeError(f"No blob links were present in the completed report: {json.dumps(report)[:4000]}")
    return links


def download_report_parts(blob_links: List[str], part_path: Path, chunk_size: int = 8 * 1024 * 1024) -> int:
    total = 0
    with part_path.open("wb") as output:
        for index, link in enumerate(blob_links, start=1):
            print(f"        Streaming part {index}/{len(blob_links)} ...", flush=True)
            # SAS URL already authorizes the blob; do not attach an ARM bearer token.
            with requests.get(link, stream=True, timeout=(60, 600), headers={"User-Agent": USER_AGENT}) as response:
                if not response.ok:
                    raise RuntimeError(
                        f"HTTP {response.status_code} downloading report part {index}: {response.text[:2000]}"
                    )
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        output.write(chunk)
                        total += len(chunk)
                        if total and total % (256 * 1024 * 1024) < chunk_size:
                            print(f"          {mib(total):,.1f} MiB downloaded", flush=True)
            output.flush()
            os.fsync(output.fileno())
    return total


def valid_cached_csv(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size <= 0:
        return False
    try:
        with path.open("rb") as handle:
            head = handle.read(4096)
        return b"," in head and (b"\n" in head or b"\r" in head)
    except OSError:
        return False


def output_name(metric: str, month_start: date) -> str:
    prefix = "Actual_Billing" if metric == "ActualCost" else "Amortized_Billing"
    return f"{prefix}_{month_start:%Y-%m}.csv"


def extract_one(http: AzureHttp, metric: str, start: date, end: date, output_dir: Path, use_cache: bool) -> Path:
    destination = output_dir / output_name(metric, start)
    partial = destination.with_suffix(destination.suffix + ".part")

    if use_cache and valid_cached_csv(destination):
        print(f"[CACHE] {destination.name} ({mib(destination.stat().st_size):,.1f} MiB)", flush=True)
        return destination

    if destination.exists():
        destination.unlink()
    if partial.exists():
        partial.unlink()

    print(f"[AZURE] {metric}: {start.isoformat()} through {end.isoformat()} ...", flush=True)
    try:
        location, initial_wait = create_report(http, metric, start, end)
        report = poll_manifest(http, location, initial_wait)
        links = get_blob_links(report)
        size = download_report_parts(links, partial)
        if size <= 0 or not valid_cached_csv(partial):
            raise RuntimeError(f"Downloaded report is empty or does not appear to be CSV: {partial}")
        partial.replace(destination)
    except Exception:
        # Keep no partial file that could later be mistaken for a complete cache entry.
        if partial.exists():
            partial.unlink()
        raise

    print(f"[SAVED] {destination.name}: {mib(destination.stat().st_size):,.1f} MiB", flush=True)
    return destination


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream monthly Azure Actual and/or Amortized Cost Details CSVs.")
    parser.add_argument("--start", required=True, type=parse_iso_date, help="Inclusive start date, YYYY-MM-DD")
    parser.add_argument("--end", required=True, type=parse_iso_date, help="Inclusive end date, YYYY-MM-DD")
    parser.add_argument("--output-dir", default="./cost_extract", help="Output directory")
    parser.add_argument(
        "--metric",
        choices=["ActualCost", "AmortizedCost", "Both"],
        default=None,
        help="Cost metric. If omitted, the program asks interactively.",
    )
    parser.add_argument("--no-cache", action="store_true", help="Redownload even when a valid monthly CSV exists")
    parser.add_argument("--timeout", type=int, default=120, help="ARM HTTP timeout in seconds")
    return parser.parse_args()


def choose_metric_interactively() -> str:
    print("Select cost data to extract:")
    print("  1. Actual Cost")
    print("  2. Amortized Cost")
    print("  3. Both Actual + Amortized Cost")
    while True:
        choice = input("Enter 1, 2, or 3 [3]: ").strip() or "3"
        mapping = {"1": "ActualCost", "2": "AmortizedCost", "3": "Both"}
        if choice in mapping:
            return mapping[choice]
        print("Please enter 1, 2, or 3.")


def format_elapsed(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def main() -> int:
    args = parse_args()
    if args.end < args.start:
        raise RuntimeError("--end must be on or after --start")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    selected_metric = args.metric or choose_metric_interactively()
    metrics = ["ActualCost", "AmortizedCost"] if selected_metric == "Both" else [selected_metric]
    tokens = AzureTokenProvider(refresh_margin_seconds=300)
    http = AzureHttp(tokens, timeout=args.timeout)
    tokens.get()

    print(f"Scope  : {SCOPE}")
    print(f"Metrics: {' + '.join(metrics)}")
    print(f"Range  : {args.start.isoformat()} through {args.end.isoformat()}")
    print(f"Output : {output_dir}\n")

    completed: List[Path] = []
    run_started = time.monotonic()
    timings = []
    for month_start, month_end in month_windows(args.start, args.end):
        month_started = time.monotonic()
        print(f"\n[TIMER] Starting {month_start:%Y-%m} ...", flush=True)
        for metric in metrics:
            file_started = time.monotonic()
            path = extract_one(http, metric, month_start, month_end, output_dir, use_cache=not args.no_cache)
            elapsed = time.monotonic() - file_started
            completed.append(path)
            timings.append((path.name, elapsed))
            print(f"[TIME]  {path.name}: {format_elapsed(elapsed)}", flush=True)
        month_elapsed = time.monotonic() - month_started
        print(f"[MONTH] {month_start:%Y-%m} completed in {format_elapsed(month_elapsed)}", flush=True)

    total_elapsed = time.monotonic() - run_started
    print("\nTiming summary:")
    for name, elapsed in timings:
        print(f"  {name:<40} {format_elapsed(elapsed)}")
    print(f"\n[DONE] {len(completed)} extracts created/reused in {format_elapsed(total_elapsed)}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[CANCELLED] Interrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"\n[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
