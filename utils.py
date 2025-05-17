import os
import json
import logging
import requests
import zipfile
from dataclasses import dataclass
from subprocess import Popen, PIPE

@dataclass
class PluginStatus:
    name: str
    status: str
    progress: float
    memory_used_mb: float
    cpu_used_percent: float

def get_plugins(console_arg, all_flag):
    # Keep existing logic
    basic_plugins = ["windows.pslist", "windows.cmdline", "windows.malfind", "windows.hashdump"]
    all_plugins = set(basic_plugins + ["windows.psscan", "windows.netscan", "windows.dlllist", "windows.svcscan"])

    if console_arg:
        return [plugin.strip() for plugin in console_arg.split(",") if plugin.strip()]
    elif all_flag:
        return list(all_plugins)
    else:
        return basic_plugins

def detect_profile_and_kdbg(memfile, vol_path):
    """Uses `windows.info` to get the suggested profile and kdbg offset."""
    cmd = [vol_path, "-f", memfile, "windows.info"]
    logging.info(f"📌 Detecting profile/KDBG: {' '.join(cmd)}")

    try:
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error("❌ windows.info failed")
            logging.error(stderr.decode(errors='ignore'))
            return None, None

        try:
            data = json.loads(stdout.decode(errors="ignore"))
        except json.JSONDecodeError as e:
            logging.error("❌ Failed to parse JSON output from windows.info")
            logging.debug(stdout.decode())
            return None, None

        profile = data.get("Suggested Profile(s)", [None])[0]
        kdbg = data.get("KDBG", {}).get("Offset")

        if profile:
            logging.info(f"🧠 Auto-detected profile: {profile}")
        if kdbg:
            logging.info(f"🎯 Auto-detected KDBG: {kdbg}")

        return profile, kdbg
    except Exception as e:
        logging.exception(f"❌ Exception during profile/KDBG detection: {e}")
        return None, None


def download_and_extract_symbols(destination="/opt/volatility3/symbols"):
    """Download all available OS symbols (Windows, macOS, Linux)."""
    SYMBOL_URLS = {
        "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
        "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
        "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
    }

    os.makedirs(destination, exist_ok=True)

    for os_name, url in SYMBOL_URLS.items():
        zip_path = os.path.join(destination, f"{os_name}.zip")

        # Only if not present
        if any(fname.startswith(os_name) for fname in os.listdir(destination)):
            logging.info(f"✅ {os_name.capitalize()} symbols already extracted.")
            continue

        try:
            logging.info(f"⬇️ Downloading {os_name} symbols...")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(8192):
                    f.write(chunk)

            logging.info(f"📦 Extracting {os_name} symbols...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(destination)

            os.remove(zip_path)
            logging.info(f"✅ {os_name} symbols ready.")
        except Exception as e:
            logging.warning(f"⚠️ Failed to download {os_name} symbols: {e}")
