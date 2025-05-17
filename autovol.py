#!/usr/bin/env python3

import sys
import argparse
from rich.console import Console
from rich.logging import RichHandler
from pyfiglet import Figlet
import logging
from executor import PluginExecutor
from dashboard import run_dashboard

console = Console()
log = logging.getLogger("AutoVol")
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler()]
)

def show_banner():
    banner = Figlet(font="slant")
    console.print(banner.renderText("AutoVol"), style="bold green")

def parse_args():
    parser = argparse.ArgumentParser(description="🎯 AutoVol - Concurrent Memory Forensics Automation")
    parser.add_argument("-f", "--file", required=True, help="Path to memory dump file")
    parser.add_argument("-d", "--directory", required=True, help="Output directory")
    parser.add_argument("-p", "--profile", help="Volatility profile (auto-detected if omitted)")
    parser.add_argument("-c", "--console", help="Comma-separated plugin list to execute")
    parser.add_argument("-a", "--all", action="store_true", help="Run all known plugins")
    parser.add_argument('-e', '--volatility-path', default='/opt/volatility3/vol.py', help="Path to vol.py")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--format", choices=["txt", "json", "html"], default="txt", help="Output format")
    parser.add_argument("--tui", action="store_true", help="Launch Textual UI dashboard")
    parser.add_argument('--download-symbols', action='store_true', help="Download Volatility 3 Windows symbol packs if not present")
    return parser.parse_args()

def main():
    args = parse_args()
    show_banner()

    executor = PluginExecutor(args)
    if args.tui:
        run_dashboard(executor)
    else:
        executor.execute()

if __name__ == "__main__":
    main()
