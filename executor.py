import os
import time
import queue
import threading
import logging
import psutil
from subprocess import Popen, PIPE
from utils import get_plugins, get_profile, PluginStatus, download_and_extract_symbols

log = logging.getLogger("AutoVol")

class PluginRunner(threading.Thread):
    def __init__(self, queue, args, status_queue=None):
        super().__init__()
        self.queue = queue
        self.args = args
        self.status_queue = status_queue
        self.process_info = psutil.Process()

    def run(self):
        while not self.queue.empty():
            plugin = self.queue.get()
            try:
                output_dir = os.path.join(self.args.directory, plugin)
                os.makedirs(output_dir, exist_ok=True)

                out_ext = self.args.format or "txt"
                out_file = os.path.join(output_dir, f"{plugin}.{out_ext}")

                cmd = [
                    self.args.volatility_path,
                    "-f", self.args.file,
                    plugin,
                    "--output", self.args.format
                ]

                log.info(f"🔹 Running: {plugin}")
                before_cpu = self.process_info.cpu_times()

                with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
                    stdout, stderr = proc.communicate()

                after_cpu = self.process_info.cpu_times()
                cpu_used = after_cpu.user - before_cpu.user
                mem_usage = self.process_info.memory_info().rss / (1024 * 1024)  # MB

                if proc.returncode != 0:
                    log.error(f"❌ Plugin {plugin} failed: {stderr.decode(errors='replace')}")
                else:
                    with open(out_file, "w", encoding="utf-8") as f:
                        f.write(stdout.decode(errors="replace"))

                    log.info(f"✅ {plugin} completed | CPU: {cpu_used:.2f}s | Memory: {mem_usage:.2f} MB")

                # TUI Dashboard info
                if self.status_queue:
                    status = PluginStatus(
                        name=plugin,
                        status="done" if proc.returncode == 0 else "error",
                        progress=1.0,
                        memory_used_mb=mem_usage,
                        cpu_used_percent=cpu_used
                    )
                    self.status_queue.put(status)

            except Exception as e:
                log.exception(f"❌ Exception while running plugin {plugin}: {e}")
            finally:
                self.queue.task_done()


class PluginExecutor:
    def __init__(self, args, download_symbols=False):
        self.args = args
        self.queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.plugins = get_plugins(args.console, args.all)
        self.profile = args.profile or get_profile(args.file, self.args.volatility_path)

        # Handle missing profile
        if not self.profile:
            raise RuntimeError("❌ Profile could not be detected from the memory file. Use --profile.")

        log.info(f"🧠 Using profile: {self.profile}")

        if download_symbols:
            log.info("📥 Attempting to download Volatility 3 symbols for all OS types...")
            download_and_extract_symbols("/opt/volatility3/symbols")

    def execute(self):
        """Run all plugins using worker threads"""
        for plugin in self.plugins:
            self.queue.put(plugin)

        for _ in range(self.args.threads):
            t = PluginRunner(self.queue, self.args)
            t.daemon = True
            t.start()
            time.sleep(0.1)

        self.queue.join()
        log.info("✅ All plugins completed.")

    def execute_with_status(self):
        """Same as `execute()`, but returns a status queue used by Textual TUI"""
        for plugin in self.plugins:
            self.queue.put(plugin)

        for _ in range(self.args.threads):
            t = PluginRunner(self.queue, self.args, self.status_queue)
            t.daemon = True
            t.start()
            time.sleep(0.1)

        return self.status_queue
