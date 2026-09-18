#!/usr/local/bin/python3.11
"""Local, administrator-authorized ZIP upgrades. Hashes are NOT signatures."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import ssl
import urllib.error
import urllib.parse
import urllib.request
import stat
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET

BASE = Path("/tmp/mwddns-upgrade")
BACKUPS = Path("/conf/mwddns-backups")
RUNTIME = Path("/var/run/mwddns")
DEBUG = Path("/tmp/mwddns-debug")
XML = Path("/usr/local/pkg/mwddns.xml")
CONFIG_HELPER = Path("/usr/local/bin/mwddns_upgrade_config.php")
RC = "/usr/local/etc/rc.d/mwddns_watcher"
MAX_ZIP = 8 * 1024 * 1024
REPOSITORY = "yatounoneko/pfSense-MWDDNS"
RELEASE_API = "https://api.github.com/repos/" + REPOSITORY + "/releases/"
RELEASE_WEB = "https://github.com/" + REPOSITORY + "/releases/"
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_RUNTIME = 64 * 1024 * 1024
ID = re.compile(r"[a-f0-9]{32}")
VERSION = re.compile(r"(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})")
REQUIRED = {
    "install.sh", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md",
    "src/usr/local/pkg/mwddns.inc", "src/usr/local/pkg/mwddns.xml",
    "src/usr/local/pkg/mwddns/debug.inc", "src/usr/local/pkg/mwddns/upgrade.inc",
    "src/usr/local/www/mwddns.php", "src/usr/local/www/mwddns_edit.php",
    "src/usr/local/www/mwddns_debug.php", "src/usr/local/www/mwddns_upgrade.php",
    "src/usr/local/www/widgets/widgets/mwddns.widget.php",
    "src/usr/local/bin/mwddns_cron.php", "src/usr/local/bin/mwddns_debug.py",
    "src/usr/local/bin/mwddns_debug_snapshot.php", "src/usr/local/bin/mwddns_upgrade.py",
    "src/usr/local/bin/mwddns_upgrade_config.php",
    "src/usr/local/bin/mwddns_gateway_watcher.py",
    "src/usr/local/etc/rc.d/mwddns_watcher",
    "src/usr/local/pkg/mwddns/cloudflare.php", "src/usr/local/pkg/mwddns/alidns.php",
    "src/usr/local/pkg/mwddns/aliesa.php", "src/usr/local/pkg/mwddns/powerdns.php",
    "src/usr/local/pkg/mwddns/locale/zh_CN.php", "src/usr/local/pkg/mwddns/locale/zh_HK.php",
}


class UpgradeError(Exception):
    pass


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise UpgradeError("VERSION_INVALID")
    return tuple(int(part) for part in value.split("."))


def regular(path, maximum):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_size > maximum:
        raise UpgradeError("UNSAFE_FILE")
    return meta


def read_json(path, maximum=65536):
    regular(path, maximum)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise UpgradeError("INVALID_STATE")
    return value


def atomic(path, value):
    tmp = path.with_name(path.name + ".tmp")
    if path.is_symlink() or tmp.is_symlink():
        raise UpgradeError("UNSAFE_FILE")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def private_dir(path, create=False):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o077:
        raise UpgradeError("UNSAFE_DIRECTORY")


def xml_version(data):
    if len(data) > 65536 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise UpgradeError("VERSION_INVALID")
    root = ET.fromstring(data)
    result = root.findtext("version", "")
    if root.tag != "packagegui" or root.findtext("name") != "mwddns":
        raise UpgradeError("VERSION_INVALID")
    version(result)
    return result


def installed_version():
    regular(XML, 65536)
    return xml_version(XML.read_bytes())


def allowed_member(name):
    if name in REQUIRED:
        return True
    # New versions may add files within the plugin namespace, not arbitrary
    # system destinations. This limits accidents, not a malicious root installer.
    return bool(re.fullmatch(
        r"src/usr/local/(?:pkg/mwddns/(?:locale/)?[a-zA-Z0-9_]+\.(?:php|inc)|"
        r"bin/mwddns_[a-zA-Z0-9_]+\.(?:php|py)|www/mwddns_[a-zA-Z0-9_]+\.php)", name))


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131072), b""):
            value.update(chunk)
    return value.hexdigest()


def inspect_archive(path, current):
    regular(path, MAX_ZIP)
    deadline = time.monotonic() + 30
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= 128:
            raise UpgradeError("ARCHIVE_LIMIT")
        seen, entries, total, root_name = set(), {}, 0, None
        for info in infos:
            if time.monotonic() >= deadline:
                raise UpgradeError("ARCHIVE_LIMIT")
            name = info.filename
            if (name != info.orig_filename or "\\" in name or ":" in name or
                    len(name) > 240 or name.startswith("/") or
                    any(part in ("", ".", "..") for part in name.split("/")) or
                    name.casefold() in seen or info.is_dir()):
                raise UpgradeError("ZIP_INVALID")
            seen.add(name.casefold())
            parts = PurePosixPath(name).parts
            if len(parts) < 2:
                raise UpgradeError("ZIP_INVALID")
            if root_name is None:
                root_name = parts[0]
            if parts[0] != root_name:
                raise UpgradeError("ZIP_INVALID")
            relative = "/".join(parts[1:])
            if relative != "mwddns-release.json" and not allowed_member(relative):
                raise UpgradeError("ZIP_INVALID")
            kind = stat.S_IFMT(info.external_attr >> 16)
            if (kind not in (0, stat.S_IFREG) or info.flag_bits & 1 or
                    info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or
                    info.file_size > MAX_FILE or info.file_size < 0):
                raise UpgradeError("ARCHIVE_LIMIT")
            total += info.file_size
            if total > MAX_EXPANDED:
                raise UpgradeError("ARCHIVE_LIMIT")
            entries[relative] = info
        if "mwddns-release.json" not in entries:
            raise UpgradeError("MANIFEST_REQUIRED")
        manifest = json.loads(archive.read(entries["mwddns-release.json"]))
        if not isinstance(manifest, dict) or manifest.get("schema") != "mwddns-release-v1" or manifest.get("name") != "mwddns":
            raise UpgradeError("ZIP_INVALID")
        target = manifest.get("version")
        if version(target) <= version(current):
            raise UpgradeError("VERSION_NOT_NEWER")
        if root_name != "pfSense-MWDDNS-" + target:
            raise UpgradeError("ZIP_INVALID")
        hashes = manifest.get("files")
        if (not isinstance(hashes, dict) or not REQUIRED.issubset(hashes) or
                set(entries) != set(hashes) | {"mwddns-release.json"}):
            raise UpgradeError("ZIP_INVALID")
        for name, expected in hashes.items():
            if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
                raise UpgradeError("HASH_MISMATCH")
            data = archive.read(entries[name])
            if len(data) != entries[name].file_size or hashlib.sha256(data).hexdigest() != expected:
                raise UpgradeError("HASH_MISMATCH")
            if time.monotonic() >= deadline:
                raise UpgradeError("ARCHIVE_LIMIT")
        installer = archive.read(entries["install.sh"])
        matches = re.findall(rb'^PKG_VERSION="([^"\r\n]+)"\s*$', installer, re.M)
        if (not installer.startswith(b"#!/bin/sh\n") or b"\r" in installer or
                matches != [target.encode("ascii")] or
                xml_version(archive.read(entries["src/usr/local/pkg/mwddns.xml"])) != target):
            raise UpgradeError("VERSION_INVALID")
        collector = archive.read(entries["src/usr/local/bin/mwddns_debug.py"])
        if re.findall(rb'"collector_version"\s*:\s*"([^"]+)"', collector) != [target.encode("ascii")]:
            raise UpgradeError("VERSION_INVALID")
    return {"version": target, "sha256": digest(path), "expanded_bytes": total, "files": hashes,
            "root": root_name}


def extract_archive(path, target, checked):
    # Never use extractall; validation is repeated immediately before this call.
    target.mkdir(mode=0o700)
    with zipfile.ZipFile(path) as archive:
        for name, expected in checked["files"].items():
            destination = target / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = archive.read(checked["root"] + "/" + name)
            if hashlib.sha256(data).hexdigest() != expected:
                raise UpgradeError("HASH_MISMATCH")
            with destination.open("xb") as handle:
                handle.write(data)
            os.chmod(destination, 0o600)


@contextlib.contextmanager
def locked(path, wait=0):
    if path.is_symlink():
        raise UpgradeError("UNSAFE_FILE")
    with path.open("a+b") as handle:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise UpgradeError("BUSY") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def checked_url(url, hosts):
    if not isinstance(url, str) or len(url) > 4096 or re.search(r"[\x00-\x20\x7f]", url):
        raise UpgradeError("RELEASE_INVALID")
    try:
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme != "https" or parts.hostname not in hosts or
                parts.port not in (None, 443) or parts.username is not None or
                parts.password is not None or parts.fragment):
            raise UpgradeError("RELEASE_INVALID")
    except ValueError:
        raise UpgradeError("RELEASE_INVALID") from None
    return url


def remote_read(url, maximum, destination=None, hosts=None):
    """No credentials, environment proxies, HTTP downgrades or arbitrary hosts."""
    hosts = hosts or {"api.github.com"}
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    deadline = time.monotonic() + 90
    for redirects in range(5):
        checked_url(url, hosts)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UpgradeError("NETWORK_TIMEOUT")
        request = urllib.request.Request(url, headers={
            "User-Agent": "pfSense-MWDDNS-updater",
            "Accept": "application/vnd.github+json" if hosts == {"api.github.com"} else "application/octet-stream",
            "Accept-Encoding": "identity",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            response = opener.open(request, timeout=min(15, remaining))
        except urllib.error.HTTPError as error:
            location, code = error.headers.get("Location"), error.code
            error.close()
            if code in (301, 302, 303, 307, 308) and location and redirects < 4:
                url = urllib.parse.urljoin(url, location)
                continue
            raise UpgradeError("RATE_LIMIT" if code in (403, 429) else
                               "NO_RELEASE" if code == 404 else "REMOTE_UNAVAILABLE") from None
        except (OSError, urllib.error.URLError):
            raise UpgradeError("REMOTE_UNAVAILABLE") from None
        with response:
            if response.status != 200:
                raise UpgradeError("REMOTE_UNAVAILABLE")
            size = response.headers.get("Content-Length")
            if size is not None and (not size.isdecimal() or int(size) > maximum):
                raise UpgradeError("DOWNLOAD_LIMIT")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise UpgradeError("RELEASE_INVALID")
            chunks, count = [], 0
            handle = destination.open("xb") if destination else contextlib.nullcontext()
            with handle as output:
                while True:
                    if time.monotonic() >= deadline:
                        raise UpgradeError("NETWORK_TIMEOUT")
                    chunk = response.read(min(65536, maximum - count + 1))
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > maximum:
                        raise UpgradeError("DOWNLOAD_LIMIT")
                    if output is not None:
                        output.write(chunk)
                    else:
                        chunks.append(chunk)
            if size is not None and count != int(size):
                raise UpgradeError("REMOTE_UNAVAILABLE")
            return count if destination else b"".join(chunks)
    raise UpgradeError("REMOTE_UNAVAILABLE")


def release_metadata(data):
    if (not isinstance(data, dict) or data.get("draft") is not False or
            data.get("prerelease") is not False):
        raise UpgradeError("RELEASE_INVALID")
    tag = data.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise UpgradeError("RELEASE_INVALID")
    target = tag[1:]
    version(target)
    if data.get("html_url") != RELEASE_WEB + "tag/" + tag:
        raise UpgradeError("RELEASE_INVALID")
    release_id = data.get("id")
    assets = data.get("assets")
    if type(release_id) is not int or release_id < 1 or not isinstance(assets, list) or len(assets) > 100:
        raise UpgradeError("RELEASE_INVALID")
    filename = "pfSense-MWDDNS-" + target + ".zip"
    matches = [item for item in assets if isinstance(item, dict) and item.get("name") == filename]
    if len(matches) != 1:
        raise UpgradeError("ASSET_INVALID")
    asset = matches[0]
    expected_url = RELEASE_WEB + "download/" + tag + "/" + filename
    size, asset_id, checksum = asset.get("size"), asset.get("id"), asset.get("digest")
    if (asset.get("state") != "uploaded" or asset.get("browser_download_url") != expected_url or
            type(size) is not int or not 1 <= size <= MAX_ZIP or
            type(asset_id) is not int or asset_id < 1 or not isinstance(checksum, str) or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", checksum)):
        raise UpgradeError("ASSET_INVALID")
    return {"version": target, "release_id": release_id, "asset_id": asset_id,
            "size": size, "sha256": checksum[7:]}


def fetch_release(target=None):
    suffix = "latest"
    if target is not None:
        version(target)
        suffix = "tags/v" + target
    data = json.loads(remote_read(RELEASE_API + suffix, 512 * 1024))
    return release_metadata(data)


@contextlib.contextmanager
def network_window():
    # A wall-clock alarm also bounds DNS lookups and slow-drip TLS responses.
    def expired(signum, frame):
        raise UpgradeError("NETWORK_TIMEOUT")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def download_release(job, current):
    saved = read_json(job / "release.json")
    checked_at = saved.get("checked_at")
    if type(checked_at) is not int or not 0 <= time.time() - checked_at < 3600:
        raise UpgradeError("RELEASE_EXPIRED")
    if version(saved.get("version")) <= version(current):
        raise UpgradeError("VERSION_NOT_NEWER")
    # Pin what the administrator saw, rather than following a moving latest URL.
    fresh = fetch_release(saved["version"])
    if any(saved.get(key) != value for key, value in fresh.items()):
        raise UpgradeError("RELEASE_CHANGED")
    name = "pfSense-MWDDNS-" + fresh["version"] + ".zip"
    url = RELEASE_WEB + "download/v" + fresh["version"] + "/" + name
    temporary = job / "download.part"
    if temporary.exists() or temporary.is_symlink():
        raise UpgradeError("UNSAFE_FILE")
    try:
        count = remote_read(url, fresh["size"], temporary, DOWNLOAD_HOSTS)
        if count != fresh["size"] or digest(temporary) != fresh["sha256"]:
            raise UpgradeError("HASH_MISMATCH")
        os.chmod(temporary, 0o600)
        destination = job / "upload.zip"
        if destination.exists() or destination.is_symlink():
            raise UpgradeError("UNSAFE_FILE")
        os.replace(temporary, destination)
    finally:
        if temporary.is_file() and not temporary.is_symlink():
            temporary.unlink()
    return fresh


def admit_checked_job(job):
    """Evict only after a newer archive has passed all checks; keep three jobs."""
    with locked(BASE / "admission.lock", wait=5):
        jobs = [path for path in BASE.glob("job-*")
                if ID.fullmatch(path.name[4:]) and path.is_dir() and not path.is_symlink()]
        if len(jobs) <= 3:
            return
        candidates = []
        idle = {"ready", "available", "current", "complete", "failed", "rolled_back"}
        for path in jobs:
            if path == job:
                continue
            try:
                private_dir(path)
                item = read_json(path / "status.json")
                if item.get("state") in idle:
                    candidates.append((int(item.get("started", 0)), path))
            except (OSError, ValueError, UpgradeError):
                continue
        for _, path in sorted(candidates):
            try:
                with locked(path / "worker.lock"):
                    item = read_json(path / "status.json")
                    if item.get("state") not in idle:
                        continue
                    # Bounded preflight: never traverse links or persistent backups.
                    started, count = time.monotonic(), 0
                    for directory, directories, files in os.walk(path, followlinks=False):
                        for name in directories + files:
                            candidate = Path(directory) / name
                            count += 1
                            if (count > 1024 or time.monotonic() - started > 2 or
                                    candidate.is_symlink() or not (candidate.is_dir() or candidate.is_file())):
                                raise UpgradeError("CLEANUP_FAILED")
                    remove_job(path)
                    jobs.remove(path)
                    if len(jobs) <= 3:
                        return
            except UpgradeError as error:
                if str(error) == "BUSY":
                    continue
                raise
        raise UpgradeError("JOB_LIMIT")


def run(argv, cwd=None, log=None, timeout=30, required=True):
    output = log.open("ab") if log else subprocess.DEVNULL
    try:
        process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            raise UpgradeError("COMMAND_TIMEOUT") from None
        if required and result != 0:
            raise UpgradeError("COMMAND_FAILED")
        return result
    finally:
        if log:
            output.close()


def runtime_files(root):
    rows, total = [], 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise UpgradeError("UNSAFE_FILE")
        for name in files:
            path = Path(directory) / name
            meta = regular(path, MAX_RUNTIME)
            if name.endswith(".lock"):
                continue
            total += meta.st_size
            rows.append((path, path.relative_to(root)))
            if len(rows) > 4096 or total > MAX_RUNTIME:
                raise UpgradeError("BACKUP_LIMIT")
    return rows, total


def copy_runtime(source, destination):
    rows, _ = runtime_files(source)
    destination.mkdir(mode=0o700, exist_ok=True)
    for path, relative in rows:
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        os.chmod(target, 0o600)


def clear_runtime(root):
    # Keep open lock-file inodes: unlinking them would allow concurrent writers.
    rows, _ = runtime_files(root)
    for path, _ in rows:
        path.unlink()
    for directory, directories, _ in os.walk(root, topdown=False, followlinks=False):
        for name in directories:
            try:
                (Path(directory) / name).rmdir()
            except OSError:
                pass


def backup_files(checked, backup):
    records = []
    for relative in checked["files"]:
        if not relative.startswith("src/"):
            continue
        destination = Path("/" + relative[4:])
        entry = {"relative": relative, "present": destination.exists()}
        if destination.is_symlink():
            raise UpgradeError("UNSAFE_FILE")
        if entry["present"]:
            meta = regular(destination, MAX_FILE)
            target = backup / "files" / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(destination, target)
            os.chmod(target, 0o600)
            entry["mode"] = stat.S_IMODE(meta.st_mode)
        records.append(entry)
    atomic(backup / "files.json", {"files": records})


def restore_files(backup):
    for entry in read_json(backup / "files.json")["files"]:
        relative = entry["relative"]
        if not isinstance(relative, str) or not relative.startswith("src/") or not allowed_member(relative):
            raise UpgradeError("INVALID_STATE")
        destination = Path("/" + relative[4:])
        if destination.is_symlink():
            raise UpgradeError("UNSAFE_FILE")
        if entry["present"]:
            source = backup / "files" / relative
            regular(source, MAX_FILE)
            temporary = destination.with_name(destination.name + ".mwddns-restore")
            if temporary.exists() or temporary.is_symlink():
                raise UpgradeError("UNSAFE_FILE")
            shutil.copyfile(source, temporary)
            os.chmod(temporary, int(entry["mode"]) & 0o777)
            os.replace(temporary, destination)
        elif destination.exists():
            regular(destination, MAX_FILE)
            destination.unlink()


def perform_install(job, state, checked):
    private_dir(RUNTIME, True)
    debug_dirs = (RUNTIME / "debug", DEBUG)
    for directory in debug_dirs:
        private_dir(directory, True)
    with contextlib.ExitStack() as guards:
        for path in (BASE / "upgrade.lock", RUNTIME / "updates.lock",
                     *(directory / "admission.lock" for directory in debug_dirs)):
            guards.enter_context(locked(path))
        if version(checked["version"]) <= version(installed_version()):
            raise UpgradeError("VERSION_NOT_NEWER")
        for directory in debug_dirs:
            for child in directory.glob("job-*"):
                private_dir(child)
                guards.enter_context(locked(child / "worker.lock"))
                status = child / "status.json"
                if not status.exists():
                    continue
                item = read_json(status)
                if item.get("state") in ("queued", "running") and time.time() - int(item.get("started", 0)) < 180:
                    raise UpgradeError("BUSY")
        request = read_json(job / "request.json")
        if request.get("mode") not in ("preserve", "reset") or request.get("trusted") is not True:
            raise UpgradeError("INVALID_STATE")
        if request["mode"] == "reset" and request.get("confirmation") != "CLEAR MWDDNS":
            raise UpgradeError("CONFIRMATION_REQUIRED")
        private_dir(BACKUPS, True)
        _, runtime_size = runtime_files(RUNTIME)
        _, debug_size = runtime_files(DEBUG)
        needed = runtime_size + debug_size + checked["expanded_bytes"] + 16 * 1024 * 1024
        if shutil.disk_usage(BACKUPS).free < needed or shutil.disk_usage(BASE).free < checked["expanded_bytes"] + 16 * 1024 * 1024:
            raise UpgradeError("DISK_SPACE")
        backup = BACKUPS / ("upgrade-" + job.name[4:])
        backup.mkdir(mode=0o700)
        state.update(state="running", stage="backing_up", backup=backup.name, mode=request["mode"])
        atomic(job / "status.json", state)
        helper = job / "config-helper.php"
        shutil.copyfile(CONFIG_HELPER, helper)
        os.chmod(helper, 0o600)
        log = job / "install.log"
        was_running = run([RC, "onestatus"], timeout=15, required=False) == 0
        changed = False
        try:
            if was_running:
                run([RC, "onestop"], log=log, timeout=20)
            run(["/usr/local/bin/php", str(helper), "backup", job.name[4:]], log=log)
            backup_files(checked, backup)
            copy_runtime(RUNTIME, backup / "runtime")
            copy_runtime(DEBUG, backup / "debug")
            atomic(backup / "backup.json", {
                "schema": "mwddns-upgrade-backup-v1", "created": int(time.time()),
                "previous_version": state["previous_version"], "target_version": checked["version"],
                "complete": True,
            })
            staged = job / "staged"
            extract_archive(job / "upload.zip", staged, checked)
            state["stage"] = "installing"
            atomic(job / "status.json", state)
            changed = True
            run(["/bin/sh", str(staged / "install.sh")], cwd=staged, log=log, timeout=180)
            if installed_version() != checked["version"]:
                raise UpgradeError("INSTALL_CHECK_FAILED")
            for relative, expected in checked["files"].items():
                if relative.startswith("src/"):
                    target = Path("/" + relative[4:])
                    regular(target, MAX_FILE)
                    if digest(target) != expected:
                        raise UpgradeError("INSTALL_CHECK_FAILED")
            if request["mode"] == "reset":
                state["stage"] = "resetting"
                atomic(job / "status.json", state)
                run([RC, "onestop"], log=log, timeout=20)
                run(["/usr/local/bin/php", str(helper), "reset", job.name[4:]], log=log)
                clear_runtime(RUNTIME)
                clear_runtime(DEBUG)
                run([RC, "onestart"], log=log, timeout=20)
            run([RC, "onestatus"], log=log, timeout=15)
            state.update(state="complete", stage="complete", finished=int(time.time()))
            atomic(job / "status.json", state)
        except Exception:
            if changed:
                state.update(state="running", stage="rolling_back")
                atomic(job / "status.json", state)
                try:
                    run([RC, "onestop"], log=log, timeout=20, required=False)
                    restore_files(backup)
                    run(["/usr/local/bin/php", str(helper), "restore", job.name[4:]], log=log)
                    clear_runtime(RUNTIME)
                    copy_runtime(backup / "runtime", RUNTIME)
                    clear_runtime(DEBUG)
                    copy_runtime(backup / "debug", DEBUG)
                    if was_running:
                        run([RC, "onestart"], log=log, timeout=20)
                    state.update(state="rolled_back", stage="rolled_back", error="INSTALL_FAILED")
                except Exception:
                    state.update(state="recovery_required", stage="recovery_required", error="RECOVERY_REQUIRED")
                atomic(job / "status.json", state)
                return
            if was_running:
                run([RC, "onestart"], log=log, timeout=20, required=False)
            raise


def remove_job(job):
    if job.parent != BASE or not ID.fullmatch(job.name.removeprefix("job-")) or not job.name.startswith("job-"):
        raise UpgradeError("INVALID_STATE")
    private_dir(job)
    # This tree is private and rooted in /tmp, never the persistent backups.
    shutil.rmtree(job)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("inspect", "install", "discard", "check", "download") or not ID.fullmatch(sys.argv[2]):
        return 2
    if os.geteuid() != 0:
        return 2
    os.umask(0o077)
    private_dir(BASE)
    job = BASE / ("job-" + sys.argv[2])
    private_dir(job)
    # Limits apply to the worker and installer descendants. No automatic restart.
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (90, 100))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RUNTIME, MAX_RUNTIME))
    owns_job = False
    try:
        with locked(job / "worker.lock"):
            owns_job = True
            if sys.argv[1] == "discard":
                # Interrupted uploads may have no valid status. Ownership and
                # path checks, not status contents, authorize temporary cleanup.
                remove_job(job)
                return 0
            state = read_json(job / "status.json")
            expected = "queued" if sys.argv[1] == "install" else "checking"
            if state.get("state") != expected or not 0 <= time.time() - int(state.get("started", 0)) < 86400:
                raise UpgradeError("EXPIRED")
            current = installed_version()
            if sys.argv[1] == "check":
                with network_window():
                    latest = fetch_release()
                atomic(job / "release.json", {**latest, "checked_at": int(time.time())})
                result = "available" if version(latest["version"]) > version(current) else "current"
                state.update(state=result, stage=result, version=latest["version"], previous_version=current)
                atomic(job / "status.json", state)
                return 0
            if sys.argv[1] == "download":
                with network_window():
                    downloaded = download_release(job, current)
                state["stage"] = "checking"
                atomic(job / "status.json", state)
            checked = inspect_archive(job / "upload.zip", current)
            if sys.argv[1] in ("inspect", "download"):
                if sys.argv[1] == "download" and checked["version"] != downloaded["version"]:
                    raise UpgradeError("VERSION_INVALID")
                admit_checked_job(job)
                state.update(state="ready", stage="ready", version=checked["version"],
                             previous_version=current, sha256=checked["sha256"])
                atomic(job / "status.json", state)
            else:
                if state.get("sha256") != checked["sha256"]:
                    raise UpgradeError("HASH_MISMATCH")
                perform_install(job, state, checked)
            return 0
    except Exception as error:
        try:
            state = read_json(job / "status.json")
            # A second worker cannot rewrite a running job's state when busy.
            if owns_job:
                state.update(state="failed", stage="failed",
                             error=str(error) if isinstance(error, UpgradeError) else "UPGRADE_FAILED")
                atomic(job / "status.json", state)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
