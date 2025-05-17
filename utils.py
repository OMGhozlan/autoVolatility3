import os
from subprocess import Popen, PIPE
from dataclasses import dataclass
import requests
import zipfile
import logging

SYMBOL_URLS = {
    "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
    "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
    "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"
}

@dataclass
class PluginStatus:
    name: str
    status: str
    progress: float
    memory_used_mb: float
    cpu_used_percent: float

def get_plugins(console_arg, all_flag):
    basic_plugins = ["windows.pslist", "windows.cmdline", "windows.malfind", "windows.hashdump"]
    all_plugins = set(basic_plugins + ["windows.psscan", "windows.netscan", "windows.dlllist", "windows.svcscan"])

    if console_arg:
        return [plugin.strip() for plugin in console_arg.split(",") if plugin.strip()]
    elif all_flag:
        return list(all_plugins)
    else:
        return basic_plugins

def get_profile(memfile, vol_path):
    cmd = f"{vol_path} -f {memfile} windows.info"
    process = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
    stdout, _ = process.communicate()
    for line in stdout.decode().splitlines():
        if "Suggested Profile(s)" in line:
            parts = line.split(":")
            if len(parts) > 1:
                return parts[1].split(",")[0].strip()
    return ""


def download_and_extract_symbols(destination="/opt/volatility3/symbols"):
    """Download and extract all OS symbols into Volatility3's symbol folder."""
    os.makedirs(destination, exist_ok=True)

    for os_name, url in SYMBOL_URLS.items():
        zip_path = os.path.join(destination, f"{os_name}.zip")

        # Skip if already extracted
        if any(fname.startswith(os_name) for fname in os.listdir(destination)):
            logging.info(f"✅ {os_name.capitalize()} symbols already present.")
            continue

        try:
            logging.info(f"⬇️  Downloading {os_name} symbols...")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            logging.info(f"📦 Extracting {os_name}.zip...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(destination)

            os.remove(zip_path)
            logging.info(f"✅ {os_name.capitalize()} symbols ready.")
        except Exception as e:
            logging.warning(f"⚠️ Failed to download {os_name} symbols: {e}")

