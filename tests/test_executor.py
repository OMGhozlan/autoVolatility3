import unittest
import os
import sys
import queue
import shutil
from unittest.mock import patch, MagicMock, call, ANY

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from executor import PluginExecutor, PluginRunner
from utils import PluginStatus # Assuming PluginStatus is imported correctly

# A dummy argparse.Namespace for testing
class MockArgs:
    def __init__(self, file="mem.raw", directory="test_output", profile="TestProfile",
                 console=None, all=False, volatility_path="vol", threads=1,
                 format="json", tui=False, log_file=None):
        self.file = file
        self.directory = directory
        self.profile = profile
        self.console = console
        self.all = all
        self.volatility_path = volatility_path
        self.threads = threads
        self.format = format
        self.tui = tui
        self.log_file = log_file

class TestPluginExecutor(unittest.TestCase):

    def setUp(self):
        self.test_output_dir = "test_executor_output"
        os.makedirs(self.test_output_dir, exist_ok=True)
        # Mock psutil.Process for memory/CPU, as it's hard to control in tests
        self.psutil_process_patch = patch('executor.psutil.Process')
        self.mock_psutil_process = self.psutil_process_patch.start()
        mock_process_instance = MagicMock()
        mock_process_instance.memory_info.return_value.rss = 100 * 1024 * 1024 # 100MB
        mock_process_instance.cpu_times.return_value.user = 1.0
        mock_process_instance.cpu_times.return_value.system = 0.5
        self.mock_psutil_process.return_value = mock_process_instance


    def tearDown(self):
        if os.path.exists(self.test_output_dir):
            shutil.rmtree(self.test_output_dir)
        self.psutil_process_patch.stop()


    @patch('executor.get_profile', return_value="DetectedProfile") # Mock profile detection
    @patch('executor.get_plugins', return_value=["windows.pslist", "windows.cmdline"]) # Mock plugin list
    @patch('executor.Popen') # Mock the actual Volatility process
    def test_executor_cli_execution_success(self, mock_popen, mock_get_plugins, mock_get_profile):
        args = MockArgs(directory=self.test_output_dir, console="windows.pslist,windows.cmdline")

        # Configure mock_popen for successful execution
        mock_proc_pslist = MagicMock()
        mock_proc_pslist.communicate.return_value = ('{"pslist_data": "success"}', '')
        mock_proc_pslist.returncode = 0

        mock_proc_cmdline = MagicMock()
        mock_proc_cmdline.communicate.return_value = ('{"cmdline_data": "success"}', '')
        mock_proc_cmdline.returncode = 0
        
        # Popen is called multiple times, once per plugin
        mock_popen.side_effect = [mock_proc_pslist, mock_proc_cmdline]

        executor = PluginExecutor(args)
        executor.execute() # Run in CLI mode (no status queue)

        # Assertions
        self.assertEqual(mock_popen.call_count, 2) # Called for each plugin
        
        # Check if output files were created (mocked Popen means we check os.path.exists on the path it would have written to)
        # We need to simulate the file writing part if Popen is fully mocked for output content.
        # For this test, let's focus on command calls and flow.
        # A better mock for Popen would involve a context manager or more complex side_effect
        # to simulate file writing based on stdout.

        # For now, let's verify the commands called
        expected_call_pslist = call(
            ['vol', '--profile', 'DetectedProfile', '-f', 'mem.raw', 'windows.pslist', '--output=json'],
            stdout=ANY, stderr=ANY, text=True, encoding='utf-8', errors='replace'
        )
        expected_call_cmdline = call(
            ['vol', '--profile', 'DetectedProfile', '-f', 'mem.raw', 'windows.cmdline', '--output=json'],
            stdout=ANY, stderr=ANY, text=True, encoding='utf-8', errors='replace'
        )
        # Order might not be guaranteed with threads, but with 1 thread and queue, it should be.
        # If using multiple threads, checking `mock_popen.call_args_list` for unordered presence is better.
        mock_popen.assert_has_calls([expected_call_pslist, expected_call_cmdline], any_order=True)

        # Check that directories for plugins were created
        self.assertTrue(os.path.exists(os.path.join(self.test_output_dir, "windows.pslist")))
        self.assertTrue(os.path.exists(os.path.join(self.test_output_dir, "windows.cmdline")))
        # Note: The actual file writing is part of PluginRunner, which needs more detailed mocking or actual Popen runs.

    @patch('executor.get_profile', return_value="DetectedProfile")
    @patch('executor.get_plugins', return_value=["windows.malfind"])
    @patch('executor.Popen')
    def test_plugin_runner_error_handling(self, mock_popen, mock_get_plugins, mock_get_profile):
        args = MockArgs(directory=self.test_output_dir, console="windows.malfind")

        mock_proc_error = MagicMock()
        mock_proc_error.communicate.return_value = ('', 'Volatility plugin error!')
        mock_proc_error.returncode = 1 # Simulate error
        mock_popen.return_value = mock_proc_error

        status_q = queue.Queue()
        plugin_q = queue.Queue()
        plugin_q.put("windows.malfind")

        runner = PluginRunner(plugin_q, args, status_q)
        runner.run() # Run the thread's main loop once for the plugin

        self.assertTrue(plugin_q.empty()) # Task should be processed
        self.assertFalse(status_q.empty()) # Status update should be sent

        final_status: PluginStatus = status_q.get_nowait()
        self.assertEqual(final_status.name, "windows.malfind")
        self.assertEqual(final_status.status, "error")
        self.assertTrue("Error (code 1)" in final_status.message)

        # Check if error file was created
        error_file_path = os.path.join(self.test_output_dir, "windows.malfind", "windows.malfind.error.txt")
        self.assertTrue(os.path.exists(error_file_path))
        with open(error_file_path, 'r') as f:
            content = f.read()
            self.assertIn("Volatility plugin error!", content)


    @patch('executor.get_profile', return_value="") # No profile detected
    @patch('executor.get_plugins', return_value=["windows.pslist"])
    @patch('executor.Popen')
    def test_executor_no_profile_proceeds(self, mock_popen, mock_get_plugins, mock_get_profile_none):
        args = MockArgs(directory=self.test_output_dir, profile=None, console="windows.pslist") # Explicitly no profile

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ('{"pslist_data": "success"}', '')
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        executor = PluginExecutor(args) # Profile detection will be called here
        self.assertEqual(executor.args.profile, "", "Profile should remain empty if detection fails")
        
        executor.execute()

        # Check that vol command is called WITHOUT --profile
        expected_call_pslist_no_profile = call(
            ['vol', '-f', 'mem.raw', 'windows.pslist', '--output=json'], # No --profile part
            stdout=ANY, stderr=ANY, text=True, encoding='utf- jornalista', errors='replace'
        )
        mock_popen.assert_has_calls([expected_call_pslist_no_profile])


    def test_executor_init_no_file(self):
        args = MockArgs(file="non_existent_memdump.raw")
        with self.assertRaises(FileNotFoundError):
            PluginExecutor(args)

if __name__ == '__main__':
    unittest.main()

