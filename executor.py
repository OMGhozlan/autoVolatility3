import os
import time
import queue
import threading
import logging
import psutil
from subprocess import Popen, PIPE
from utils import (
    get_plugins,
    detect_profile_and_kdbg,
    download_and_extract_symbols,
    PluginStatus,
)

log = logging.getLogger("AutoVol")


class PluginRunner(threading.Thread):
    def __init__(self, queue, args, status_queue=None, profile=None, kdbg=None):
        super().__init__()
        self.queue = queue
        self.args = args
        self.status_queue = status_queue
        self.profile = profile
        self.kdbg = kdbg
        self.process_info = psutil.Process()

    def run(self):
        while not self.queue.empty():
            plugin = self.queue.get()

            try:
                output_dir = os.path.join(self.args.directory, plugin)
                os.makedirs(output_dir, exist_ok=True)                    

                cmd = [self.args.volatility_path, "-f", self.args.file, plugin]
                
                out_ext = self.args.format if "--output" in cmd else "txt"
                out_file = os.path.join(output_dir, f"{plugin}.{out_ext}")


                # Only add --output if supported
                if self.args.format != "txt":
                    help_cmd = [self.args.volatility_path, plugin, "-h"]
                    try:
                        proc = Popen(help_cmd, stdout=PIPE, stderr=PIPE)
                        stdout, _ = proc.communicate()
                        if b"--output" in stdout:
                            cmd += ["--output", self.args.format]
                        else:
                            log.warning(f"⚠️ Plugin {plugin} does not support --output={self.args.format}. Falling back to raw text.")
                    except Exception as e:
                        log.warning(f"Could not check output support for {plugin}: {e}")


                # Append auto-detected profile and kdbg if needed
                # if "windows" in plugin and self.profile:
                #     cmd += ["--profile", self.profile]
                if "windows" in plugin and self.kdbg:
                    cmd += ["--kdbg", self.kdbg]

                log.info(f"🔹 Running plugin: {plugin} with command {cmd}")
                before_cpu = self.process_info.cpu_times()

                with Popen(cmd, stdout=PIPE, stderr=PIPE) as proc:
                    stdout, stderr = proc.communicate()

                after_cpu = self.process_info.cpu_times()
                cpu_used = after_cpu.user - before_cpu.user
                mem_usage = self.process_info.memory_info().rss / (1024 * 1024)  # MB

                # Save output
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(stdout.decode(errors="replace"))

                if proc.returncode != 0:
                    log.error(f"❌ Plugin {plugin} failed with error:\n{stderr.decode(errors='replace')}")
                    status = PluginStatus(plugin, "error", 1.0, mem_usage, cpu_used)
                else:
                    log.info(f"✅ Completed {plugin} | CPU: {cpu_used:.2f}s | MEM: {mem_usage:.2f}MB")
                    status = PluginStatus(plugin, "done", 1.0, mem_usage, cpu_used)

                if self.status_queue:
                    self.status_queue.put(status)

            except Exception as e:
                log.exception(f"❌ Exception in {plugin}: {e}")
            finally:
                self.queue.task_done()


class PluginExecutor:
    def __init__(self, args, download_symbols=False):
        self.args = args
        self.queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.plugins = get_plugins(args.console, args.all)

        self.profile = args.profile
        self.kdbg = None

        if not self.profile:
            log.info("🔍 Detecting memory profile and KDBG offset...")
            self.profile, self.kdbg = detect_profile_and_kdbg(args.file, args.volatility_path)

        # if not self.profile:
        #     raise RuntimeError("❌ Profile could not be detected. Use --profile manually to proceed.")

        log.info(f"🧠 Using profile: {self.profile}")
        if self.kdbg:
            log.info(f"🎯 Using KDBG offset: {self.kdbg}")

        if download_symbols:
            log.info("📥 Downloading required Volatility 3 symbols...")
            download_and_extract_symbols("/opt/volatility3/symbols")

    def execute(self):
        """Run plugins using worker threads"""
        for plugin in self.plugins:
            self.queue.put(plugin)

        for _ in range(self.args.threads):
            t = PluginRunner(self.queue, self.args, None, self.profile, self.kdbg)
            t.daemon = True
            t.start()
            time.sleep(0.1)

        self.queue.join()
        log.info("✅ All plugins completed.")

    def execute_with_status(self):
        """Run plugins and return a queue for TUI status updates"""
        for plugin in self.plugins:
            self.queue.put(plugin)

        for _ in range(self.args.threads):
            t = PluginRunner(self.queue, self.args, self.status_queue, self.profile, self.kdbg)
            t.daemon = True
            t.start()
            time.sleep(0.1)

        return self.status_queue
