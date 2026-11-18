"""Launcher that runs the WaysGram bot code stored in the WaysGram-New repository.

Paste this file into the `WaysGram-AuthBot` repository as `bot.py` and keep that repository
selected in BotHost. At every start it fetches only the bot folder (`authbot/`) from
`WeteroScript/WaysGram-New` and executes it, so the code you edit lives in WaysGram-New while the
hosting panel keeps pointing at a small repository.

How the folder is fetched:

1. `api` (default) - one request resolves the commit, one returns the file tree, the rest download
   the *.py/tests of `authbot/` only (~1.3 MB). Nothing else of the Android repository is touched.
2. `archive` - fallback when the GitHub API is rate limited: the repository archive is downloaded
   and only `authbot/` is unpacked from it.
3. cache `<WAYSGRAM_HOME>/<commit>/authbot` - used when GitHub cannot be reached at all.

Environment variables (all optional):

    WAYSGRAM_REPO         default WeteroScript/WaysGram-New
    WAYSGRAM_REF          branch or tag, default arena/00b4c974-waysgram-new
    WAYSGRAM_COMMIT       pin an exact commit (skips update checks)
    WAYSGRAM_SUBDIR       folder with the bot code, default authbot
    WAYSGRAM_HOME         cache directory, default /data/waysgram-new, else ./.waysgram-src
    WAYSGRAM_MODE         auto | api | archive
    AUTHBOT_GITHUB_TOKEN  raises the API rate limit and allows a private repository
    AUTHBOT_SYNC_DEPS     1 = install the pulled requirements.txt before start

Diagnostics: `python bot.py --check` shows the resolved commit and the folder, starts nothing.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))

DEFAULT_REPO = "WeteroScript/WaysGram-New"
DEFAULT_REF = "arena/00b4c974-waysgram-new"
DEFAULT_SUBDIR = "authbot"
ENTRY_NAME = "bot.py"
HTTP_TIMEOUT = 30
PARALLEL_DOWNLOADS = 8


def log(message: str) -> None:
    sys.stderr.write(f"[waysgram-launcher] {message}\n")
    sys.stderr.flush()


def _env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None or value == "" else value


def cache_home() -> str:
    configured = _env("WAYSGRAM_HOME")
    if configured:
        return os.path.abspath(configured)
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data/waysgram-new"
    return os.path.join(ROOT, ".waysgram-src")


def _open(url: str, token: str, accept: str = "application/vnd.github+json"):
    request = urllib.request.Request(url, headers={"User-Agent": "waysgram-launcher", "Accept": accept})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    return urllib.request.urlopen(request, timeout=HTTP_TIMEOUT)


def _json(url: str, token: str) -> dict:
    with _open(url, token) as response:
        return json.loads(response.read().decode("utf-8"))


def _bytes(url: str, token: str, accept: str = "application/vnd.github+json") -> bytes:
    with _open(url, token, accept) as response:
        return response.read()


def resolve_commit(repo: str, ref: str, token: str) -> str:
    try:
        return str(_json(f"https://api.github.com/repos/{repo}/commits/{ref}", token)["sha"]).strip()
    except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
        log(f"cannot resolve {repo}@{ref} ({type(error).__name__}); "
            "the archive or the cache will be used")
        return ""


def list_files(repo: str, sha: str, subdir: str, token: str) -> list[tuple[str, str, int]]:
    """Returns (path relative to subdir, blob sha, size) for every file under subdir."""
    tree = _json(f"https://api.github.com/repos/{repo}/git/trees/{sha}?recursive=1", token)
    if tree.get("truncated"):
        raise RuntimeError("the repository tree is truncated; use WAYSGRAM_MODE=archive")
    prefix = f"{subdir.strip('/')}/"
    files = []
    for entry in tree.get("tree", []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path", "")
        if not path.startswith(prefix):
            continue
        files.append((path[len(prefix):], entry["sha"], int(entry.get("size", 0))))
    if not files:
        raise RuntimeError(f"{repo}@{sha[:12]} has no files in {prefix}")
    return files


def fetch_blob(repo: str, blob_sha: str, token: str) -> bytes:
    payload = _json(f"https://api.github.com/repos/{repo}/git/blobs/{blob_sha}", token)
    if payload.get("encoding") != "base64":
        raise RuntimeError(f"unexpected blob encoding: {payload.get('encoding')}")
    return base64.b64decode(payload["content"])


def materialize_api(repo: str, sha: str, subdir: str, token: str, target: str) -> int:
    files = list_files(repo, sha, subdir, token)
    total = sum(size for _, _, size in files)
    log(f"downloading {len(files)} files ({total / 1024:.0f} KiB) from {repo}@{sha[:12]}/{subdir}")

    def download(item):
        relative, blob_sha, _size = item
        return relative, fetch_blob(repo, blob_sha, token)

    with ThreadPoolExecutor(max_workers=PARALLEL_DOWNLOADS) as pool:
        for relative, content in pool.map(download, files):
            parts = [part for part in relative.split("/") if part not in ("", ".")]
            if not parts or ".." in parts:
                continue
            destination = os.path.join(target, *parts)
            os.makedirs(os.path.dirname(destination) or target, exist_ok=True)
            with open(destination, "wb") as handle:
                handle.write(content)
    return len(files)


def materialize_archive(repo: str, ref_or_sha: str, subdir: str, token: str, target: str) -> int:
    log(f"downloading the archive of {repo}@{ref_or_sha[:12]}")
    try:
        payload = _bytes(
            f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{ref_or_sha}",
            token, accept="application/octet-stream",
        )
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        payload = _bytes(
            f"https://codeload.github.com/{repo}/tar.gz/{ref_or_sha}",
            token, accept="application/octet-stream",
        )

    prefix_parts = subdir.strip("/").split("/")
    written = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = [part for part in member.name.split("/") if part not in ("", ".")]
            if not parts:
                continue
            parts = parts[1:]  # drop the "repo-ref/" prefix
            if parts[:len(prefix_parts)] != prefix_parts:
                continue
            relative = parts[len(prefix_parts):]
            if not relative or ".." in relative or not member.isfile():
                continue
            destination = os.path.join(target, *relative)
            os.makedirs(os.path.dirname(destination) or target, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with open(destination, "wb") as handle:
                shutil.copyfileobj(source, handle)
            written += 1
    if not written:
        raise RuntimeError(f"the archive of {repo} has no {subdir}/ files")
    return written


def latest_cached(home: str, subdir: str) -> str:
    if not os.path.isdir(home):
        return ""
    candidates = [
        name for name in os.listdir(home)
        if not name.startswith(".") and os.path.isfile(os.path.join(home, name, subdir, ENTRY_NAME))
    ]
    if not candidates:
        return ""
    candidates.sort(key=lambda name: os.path.getmtime(os.path.join(home, name, subdir)), reverse=True)
    return os.path.join(home, candidates[0], subdir)


def ensure_source(repo: str, ref: str, subdir: str, pinned: str, mode: str, token: str, home: str) -> str:
    os.makedirs(home, exist_ok=True)
    sha = pinned or resolve_commit(repo, ref, token)

    if sha:
        cached = os.path.join(home, sha, subdir)
        if os.path.isfile(os.path.join(cached, ENTRY_NAME)):
            log(f"using cached commit {sha[:12]}")
            return cached

    staging = tempfile.mkdtemp(prefix=".staging-", dir=home)
    try:
        staging_source = os.path.join(staging, subdir)
        os.makedirs(staging_source, exist_ok=True)
        written = 0
        errors = []
        if mode in ("auto", "api") and sha:
            try:
                written = materialize_api(repo, sha, subdir, token, staging_source)
            except Exception as error:  # noqa: BLE001 - rate limits and network hiccups land here
                errors.append(f"api: {type(error).__name__}: {error}")
                log(f"api download failed: {type(error).__name__}: {error}")
        if not written and mode in ("auto", "archive"):
            try:
                written = materialize_archive(repo, sha or ref, subdir, token, staging_source)
            except Exception as error:  # noqa: BLE001
                errors.append(f"archive: {type(error).__name__}: {error}")
                log(f"archive download failed: {type(error).__name__}: {error}")
        if not written or not os.path.isfile(os.path.join(staging_source, ENTRY_NAME)):
            raise RuntimeError("; ".join(errors) or f"{subdir}/{ENTRY_NAME} is missing")
        # Without a resolved commit the ref itself names the cache entry; the next start with a
        # reachable API replaces it with the exact commit directory.
        cache_key = sha or "ref-" + "".join(
            character if character.isalnum() else "-" for character in ref
        ).strip("-")
        target = os.path.join(home, cache_key)
        if os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)
        os.replace(staging, target)
        log(f"unpacked {written} files into {os.path.join(target, subdir)}")
        return os.path.join(target, subdir)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def resolve_entry(repo: str, ref: str, subdir: str, pinned: str, mode: str, token: str, home: str) -> str:
    try:
        return os.path.join(ensure_source(repo, ref, subdir, pinned, mode, token, home), ENTRY_NAME)
    except Exception as error:  # noqa: BLE001
        log(f"remote pull failed ({type(error).__name__}: {error})")
        if mode in ("api", "archive"):
            raise
    cached = latest_cached(home, subdir)
    if cached:
        log(f"using the cached copy {cached}")
        return os.path.join(cached, ENTRY_NAME)
    raise RuntimeError("no bot sources: GitHub is unreachable and the cache is empty")


def sync_dependencies(source_dir: str) -> None:
    requirements = os.path.join(source_dir, "requirements.txt")
    if not os.path.isfile(requirements):
        return
    log("AUTHBOT_SYNC_DEPS=1: installing the pulled requirements")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-cache-dir", "-r", requirements], check=True
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="WaysGram bot launcher")
    parser.add_argument("--check", action="store_true", help="pull the code and print where it landed")
    parser.add_argument("--repo", default=_env("WAYSGRAM_REPO", DEFAULT_REPO))
    parser.add_argument("--ref", default=_env("WAYSGRAM_REF", DEFAULT_REF))
    parser.add_argument("--subdir", default=_env("WAYSGRAM_SUBDIR", DEFAULT_SUBDIR))
    parser.add_argument("--commit", default=_env("WAYSGRAM_COMMIT"))
    parser.add_argument("--mode", default=_env("WAYSGRAM_MODE", "auto"),
                        choices=("auto", "api", "archive"))
    args = parser.parse_args()

    token = _env("AUTHBOT_GITHUB_TOKEN")
    home = cache_home()
    try:
        entry = resolve_entry(args.repo, args.ref, args.subdir, args.commit, args.mode, token, home)
    except Exception as error:  # noqa: BLE001 - one readable line instead of a traceback
        log(f"cannot obtain the bot sources: {type(error).__name__}: {error}")
        return 2

    source_dir = os.path.dirname(entry)
    if not os.path.isfile(entry):
        log(f"{entry} is missing")
        return 2

    if args.check:
        print(json.dumps({
            "source": source_dir,
            "entry": entry,
            "repo": args.repo,
            "ref": args.ref,
            "subdir": args.subdir,
            "commit": os.path.basename(source_dir),
            "cache_home": home,
        }, ensure_ascii=False, indent=2))
        return 0

    if _env("AUTHBOT_SYNC_DEPS", "0") == "1":
        sync_dependencies(source_dir)

    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)

    import runpy

    runpy.run_path(entry, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
