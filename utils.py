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

def get_plugins(console_arg=None, dump_flag=False):
    # Plugin categories
    volatility_plugins = {
        "linux": [
            "linux.bash.Bash",
            "linux.boottime.Boottime",
            "linux.capabilities.Capabilities",
            "linux.check_afinfo.Check_afinfo",
            "linux.check_creds.Check_creds",
            "linux.check_idt.Check_idt",
            "linux.check_modules.Check_modules",
            "linux.check_syscall.Check_syscall",
            "linux.ebpf.EBPF",
            "linux.elfs.Elfs",
            "linux.envars.Envars",
            "linux.graphics.fbdev.Fbdev",
            "linux.hidden_modules.Hidden_modules",
            "linux.iomem.IOMem",
            "linux.ip.Addr",
            "linux.ip.Link",
            "linux.kallsyms.Kallsyms",
            "linux.keyboard_notifiers.Keyboard_notifiers",
            "linux.kmsg.Kmsg",
            "linux.kthreads.Kthreads",
            "linux.library_list.LibraryList",
            "linux.lsmod.Lsmod",
            "linux.lsof.Lsof",
            "linux.malfind.Malfind",
            "linux.module_extract.ModuleExtract",
            "linux.modxview.Modxview",
            "linux.mountinfo.MountInfo",
            "linux.netfilter.Netfilter",
            "linux.pagecache.Files",
            "linux.pagecache.InodePages",
            "linux.pagecache.RecoverFs",
            "linux.pidhashtable.PIDHashTable",
            "linux.proc.Maps",
            "linux.psaux.PsAux",
            "linux.pscallstack.PsCallStack",
            "linux.pslist.PsList",
            "linux.psscan.PsScan",
            "linux.pstree.PsTree",
            "linux.ptrace.Ptrace",
            "linux.sockstat.Sockstat",
            "linux.tracing.ftrace.CheckFtrace",
            "linux.tracing.perf_events.PerfEvents",
            "linux.tracing.tracepoints.CheckTracepoints",
            "linux.tty_check.tty_check",
            "linux.vmaregexscan.VmaRegExScan",
            "linux.vmayarascan.VmaYaraScan",
            "linux.vmcoreinfo.VMCoreInfo",
        ],
        "mac": [
            "mac.bash.Bash",
            "mac.check_syscall.Check_syscall",
            "mac.check_sysctl.Check_sysctl",
            "mac.check_trap_table.Check_trap_table",
            "mac.dmesg.Dmesg",
            "mac.ifconfig.Ifconfig",
            "mac.kauth_listeners.Kauth_listeners",
            "mac.kauth_scopes.Kauth_scopes",
            "mac.kevents.Kevents",
            "mac.list_files.List_Files",
            "mac.lsmod.Lsmod",
            "mac.lsof.Lsof",
            "mac.malfind.Malfind",
            "mac.mount.Mount",
            "mac.netstat.Netstat",
            "mac.proc_maps.Maps",
            "mac.psaux.Psaux",
            "mac.pslist.PsList",
            "mac.pstree.PsTree",
            "mac.socket_filters.Socket_filters",
            "mac.timers.Timers",
            "mac.trustedbsd.Trustedbsd",
            "mac.vfsevents.VFSevents",
        ],
        "windows": [
            "windows.amcache.Amcache",
            "windows.bigpools.BigPools",
            "windows.cachedump.Cachedump",
            "windows.callbacks.Callbacks",
            "windows.cmdline.CmdLine",
            "windows.cmdscan.CmdScan",
            "windows.consoles.Consoles",
            "windows.crashinfo.Crashinfo",
            "windows.debugregisters.DebugRegisters",
            "windows.deskscan.DeskScan",
            "windows.desktops.Desktops",
            "windows.devicetree.DeviceTree",
            "windows.direct_system_calls.DirectSystemCalls",
            "windows.dlllist.DllList",
            "windows.driverirp.DriverIrp",
            "windows.drivermodule.DriverModule",
            "windows.driverscan.DriverScan",
            "windows.dumpfiles.DumpFiles",
            "windows.envars.Envars",
            "windows.etwpatch.EtwPatch",
            "windows.filescan.FileScan",
            "windows.getservicesids.GetServiceSIDs",
            "windows.getsids.GetSIDs",
            "windows.handles.Handles",
            "windows.hashdump.Hashdump",
            "windows.hollowprocesses.HollowProcesses",
            "windows.iat.IAT",
            "windows.indirect_system_calls.IndirectSystemCalls",
            "windows.info.Info",
            "windows.joblinks.JobLinks",
            "windows.kpcrs.KPCRs",
            "windows.ldrmodules.LdrModules",
            "windows.lsadump.Lsadump",
            "windows.malfind.Malfind",
            "windows.mbrscan.MBRScan",
            "windows.memmap.Memmap",
            "windows.mftscan.ADS",
            "windows.mftscan.MFTScan",
            "windows.mftscan.ResidentData",
            "windows.modscan.ModScan",
            "windows.modules.Modules",
            "windows.mutantscan.MutantScan",
            "windows.netscan.NetScan",
            "windows.netstat.NetStat",
            "windows.orphan_kernel_threads.Threads",
            "windows.pe_symbols.PESymbols",
            "windows.pedump.PEDump",
            "windows.poolscanner.PoolScanner",
            "windows.privileges.Privs",
            "windows.processghosting.ProcessGhosting",
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.pstree.PsTree",
            "windows.psxview.PsXView",
            "windows.registry.amcache.Amcache",
            "windows.registry.cachedump.Cachedump",
            "windows.registry.certificates.Certificates",
            "windows.registry.getcellroutine.GetCellRoutine",
            "windows.registry.hashdump.Hashdump",
            "windows.registry.hivelist.HiveList",
            "windows.registry.hivescan.HiveScan",
            "windows.registry.lsadump.Lsadump",
            "windows.registry.printkey.PrintKey",
            "windows.registry.scheduled_tasks.ScheduledTasks",
            "windows.registry.userassist.UserAssist",
            "windows.scheduled_tasks.ScheduledTasks",
            "windows.sessions.Sessions",
            "windows.shimcachemem.ShimcacheMem",
            "windows.skeleton_key_check.Skeleton_Key_Check",
            "windows.ssdt.SSDT",
            "windows.statistics.Statistics",
            "windows.strings.Strings",
            "windows.suspended_threads.SuspendedThreads",
            "windows.suspicious_threads.SuspiciousThreads",
            "windows.svcdiff.SvcDiff",
            "windows.svclist.SvcList",
            "windows.svcscan.SvcScan",
            "windows.symlinkscan.SymlinkScan",
            "windows.thrdscan.ThrdScan",
            "windows.threads.Threads",
            "windows.timers.Timers",
            "windows.truecrypt.Passphrase",
            "windows.unhooked_system_calls.unhooked_system_calls",
            "windows.unloadedmodules.UnloadedModules",
            "windows.vadinfo.VadInfo",
            "windows.vadregexscan.VadRegExScan",
            "windows.vadwalk.VadWalk",
            "windows.vadyarascan.VadYaraScan",
            "windows.verinfo.VerInfo",
            "windows.virtmap.VirtMap",
            "windows.windows.Windows",
            "windows.windowstations.WindowStations",
        ],
        "common": [  # Don't have OS-specific prefixes
            "banners.Banners",
            "configwriter.ConfigWriter",
            "frameworkinfo.FrameworkInfo",
            "isfinfo.IsfInfo",
            "layerwriter.LayerWriter",
            "regexscan.RegExScan",
            "timeliner.Timeliner",
            "vmscan.Vmscan",
            "yarascan.YaraScan",
        ]
    }

    # Get all plugins flat
    all_plugins = []
    for category_plugins in volatility_plugins.values():
        all_plugins.extend(category_plugins)
    all_plugins = sorted(set(all_plugins))

    selected_plugins = set()

    if console_arg:
        # Accept multiple categories separated by +
        categories = set(part.strip().lower() for part in console_arg.split('+') if part.strip())

        for cat in categories:
            # Support direct plugins (e.g. plugin names), not just category names
            if cat in volatility_plugins:
                selected_plugins.update(volatility_plugins[cat])
            else:
                # Try partial match: maybe user passed direct plugin names or typos
                matched_plugins = [p for plist in volatility_plugins.values() for p in plist if p.lower() == cat]
                if matched_plugins:
                    selected_plugins.update(matched_plugins)
                else:
                    print(f"⚠️ Unknown plugin or category: '{cat}'")
    elif dump_flag:
        selected_plugins = {
            "windows.dumpfiles.DumpFiles",
            "linux.pagecache.RecoverFs",
        }
    else:
        selected_plugins = set(volatility_plugins["common"])

    return sorted(selected_plugins)


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
