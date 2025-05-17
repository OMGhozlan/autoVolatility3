import os
import json
import re
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

def get_plugins(console_arg=None, all_flag=False, dump_flag=False):
    # Plugin categories
    dump_plugins = {"dumpcerts", "dumpregistry", "dumpfiles", "servicediff", "hashdump"}

    common_plugins = {
        "amcache", "auditpol", "cachedump", "clipboard", "cmdline", "cmdscan", "connections",
        "connscan", "consoles", "deskscan", "devicetree", "dlllist", "envars", "getservicesids",
        "handles", "hashdump", "hibinfo", "hivelist", "hivescan", "iehistory", "ldrmodules",
        "lsadump", "malfind", "mbrparser", "memmap", "mftparser", "modules", "notepad", "privs",
        "pslist", "psscan", "pstree", "psxview", "qemuinfo", "servicediff", "sessions", "sockets",
        "sockscan", "ssdt", "strings", "svcscan", "symlinkscan", "thrdscan", "verinfo", "windows",
        "wintree"
    }

    all_plugins = {
        "amcache", "apihooks", "atoms", "atomscan", "auditpol", "bigpools", "bioskbd", "cachedump",
        "callbacks", "clipboard", "cmdline", "cmdscan", "connections", "connscan", "consoles",
        "crashinfo", "deskscan", "devicetree", "dlldump", "dlllist", "driverirp", "drivermodule",
        "driverscan", "editbox", "envars", "eventhooks", "evtlogs", "filescan", "gahti", "gditimers",
        "gdt", "getservicesids", "getsids", "handles", "hashdump", "hibinfo", "hivelist", "hivescan",
        "hpakextract", "hpakinfo", "idt", "iehistory", "imagecopy", "imageinfo", "joblinks",
        "kdbgscan", "kpcrscan", "ldrmodules", "lsadump", "malfind", "mbrparser", "memdump",
        "memmap", "messagehooks", "mftparser", "moddump", "modscan", "modules", "multiscan",
        "mutantscan", "notepad", "objtypescan", "patcher", "printkey", "privs", "procdump",
        "pslist", "psscan", "pstree", "psxview", "qemuinfo", "raw2dmp", "sessions", "shellbags",
        "shimcache", "shutdowntime", "sockets", "sockscan", "ssdt", "strings", "svcscan",
        "symlinkscan", "thrdscan", "threads", "timeliner", "timers", "truecryptmaster",
        "truecryptpassphrase", "truecryptsummary", "unloadedmodules", "userassist", "userhandles",
        "vaddump", "vadinfo", "vadtree", "vadwalk", "vboxinfo", "verinfo", "vmwareinfo", "windows",
        "wintree", "wndscan"
    }

    # Selection logic
    if console_arg:
        selected = {p.strip().lower() for p in console_arg.split(",") if p.strip()}
    elif all_flag:
        selected = all_plugins
    elif dump_flag:
        selected = dump_plugins
    else:
        selected = common_plugins

    # Return sorted list of unique plugins
    return sorted(selected)


def detect_profile_and_kdbg(memfile, vol_path):
    """Parses text output of `windows.info` plugin to extract profile and KDBG offset."""
    cmd = [vol_path, "-f", memfile, "windows.info"]
    logging.info(f"📌 Detecting profile/KDBG: {' '.join(cmd)}")

    try:
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            logging.error("❌ windows.info failed")
            logging.error(stderr.decode(errors='ignore'))
            return None, None

        output = stdout.decode(errors='ignore')

        # Log raw output for debugging/investigation
        logging.debug("ℹ️ windows.info output:\n" + output)

        profile = None
        kdbg = None

        # 1. Extract profile from "Symbols" line
        match_profile = re.search(r"Symbols\s+(.*)", output)
        if match_profile:
            symbol_path = match_profile.group(1).strip()
            # Extract profile: filename before first '/' in the pdb path
            profile_match = re.search(r"windows/([\w\.]+)/", symbol_path)
            if profile_match:
                profile = profile_match.group(1)
                logging.info(f"🧠 Detected profile: {profile}")

        # 2. Extract KDBG from KdVersionBlock line
        match_kdbg = re.search(r"KdVersionBlock\s+(0x[0-9a-fA-F]+)", output)
        if match_kdbg:
            kdbg = match_kdbg.group(1)
            logging.info(f"🎯 Detected KDBG offset: {kdbg}")

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

def list_json_capable_plugins(vol_path):
    """Lists available plugins that support --output json."""
    cmd = [vol_path, "--info"]
    try:
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode(errors='ignore')

        plugin_support_map = {}

        cur_plugin = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Plugin:"):
                cur_plugin = line.split(":", 1)[1].strip()
                plugin_support_map[cur_plugin] = []
            elif line.startswith("Supported Output Formats:") and cur_plugin:
                formats = [fmt.strip() for fmt in line.split(":")[1].split(",")]
                plugin_support_map[cur_plugin] = formats

        json_plugins = [name for name, formats in plugin_support_map.items() if "JSON" in (fmt.upper() for fmt in formats)]
        return json_plugins

    except Exception as e:
        logging.exception("❌ Failed to fetch plugin output support list.")
        return []
