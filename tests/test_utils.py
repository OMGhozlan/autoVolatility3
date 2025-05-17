import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add project root to sys.path to allow importing AutoVol modules
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from utils import get_plugins, get_profile, PluginStatus

class TestUtils(unittest.TestCase):

    def test_get_plugins_default(self):
        plugins = get_plugins(None, False)
        self.assertIsInstance(plugins, list)
        self.assertTrue(len(plugins) > 0, "Default plugin list should not be empty")
        self.assertIn("windows.pslist", plugins, "Default list should contain pslist")

    def test_get_plugins_all_flag(self):
        plugins = get_plugins(None, True)
        self.assertIsInstance(plugins, list)
        # Assuming 'all' list is longer than default
        default_len = len(get_plugins(None, False))
        self.assertTrue(len(plugins) > default_len, "'All' plugin list should be longer than default")
        self.assertIn("windows.malfind", plugins, "'All' list should contain malfind")

    def test_get_plugins_console_arg(self):
        console_str = "windows.pslist,windows.cmdline"
        plugins = get_plugins(console_str, False)
        self.assertEqual(len(plugins), 2)
        self.assertEqual(plugins, ["windows.pslist", "windows.cmdline"])

        plugins_with_spaces = get_plugins("  windows.pslist  ,  windows.cmdline ", False)
        self.assertEqual(plugins_with_spaces, ["windows.pslist", "windows.cmdline"])

        empty_console_str = ""
        plugins_empty = get_plugins(empty_console_str, False)
        self.assertEqual(plugins_empty, [])


    @patch('utils.Popen')
    def test_get_profile_success_windows(self, mock_popen):
        # Simulate Volatility 3 windows.info output
        mock_stdout_content = """
Volatility 3 Framework 2.x.x
INFO     volatility3.cli: Volatility plugins path: ['/opt/volatility3/volatility3/plugins']
INFO     volatility3.cli: Volatility symbols path: ['/app/volatility3/symbols']
Architecture        🕒 Time             Layer Name            Filename
------------        ----------         ----------            --------
IntelAMD64          2023-01-01T00:00:00Z Primary               /memdumps/test.vmem

Progress:  100.00		PDB scanning finished                        
INFO     volatility3.framework. выбора: No suitable symbol table found
INFO     volatility3.framework. lựa chọn: No suitable symbol table found

Symbol table suggestions:
-------------------------
Win10x64_19041      ['ntkrnlmp.pdb', 'GUID1']   Windows 10 Kernel Version 19041 UP
Win7SP1x86_23418    ['ntkrnlpa.pdb', 'GUID2']   Windows 7 Kernel Version 7601 SP1 UP X86 Multiprocessor Free
LinuxTest           ['vmlinux.pdb', 'GUID3']    Some Linux

        """
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (mock_stdout_content, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        profile = get_profile("/path/to/memfile.vmem", "vol")
        self.assertEqual(profile, "Win10x64_19041") # Expects the first valid-looking one
        mock_popen.assert_called_once_with(
            ['vol', '-f', '"/path/to/memfile.vmem"', 'windows.info'], # Check if quotes are handled
            stdout=-1, stderr=-1, text=True, encoding='utf-8', errors='replace'
        )


    @patch('utils.Popen')
    def test_get_profile_no_suggestion(self, mock_popen):
        mock_stdout_content = """
Volatility 3 Framework 2.x.x
Architecture        🕒 Time             Layer Name            Filename
------------        ----------         ----------            --------
IntelAMD64          2023-01-01T00:00:00Z Primary               /memdumps/test.vmem

Symbol table suggestions:
-------------------------
        """ # Empty suggestions
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (mock_stdout_content, "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        profile = get_profile("mem.raw", "vol")
        self.assertEqual(profile, "")

    @patch('utils.Popen')
    def test_get_profile_volatility_error(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "Some Volatility Error")
        mock_proc.returncode = 1 # Non-zero return code
        mock_popen.return_value = mock_proc

        profile = get_profile("mem.raw", "vol")
        self.assertEqual(profile, "")

    @patch('utils.Popen')
    def test_get_profile_timeout(self, mock_popen):
        from subprocess import TimeoutExpired
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = TimeoutExpired(cmd="vol ...", timeout=1)
        # mock_proc.kill = MagicMock() # Ensure kill is callable
        mock_popen.return_value = mock_proc
        
        profile = get_profile("mem.raw", "vol")
        self.assertEqual(profile, "")
        mock_proc.kill.assert_called_once()


    def test_plugin_status_dataclass(self):
        status = PluginStatus(
            name="test.plugin",
            status="running",
            progress=0.5,
            memory_used_mb=100.5,
            cpu_used_percent=25.5,
            message="In progress"
        )
        self.assertEqual(status.name, "test.plugin")
        self.assertEqual(status.message, "In progress")

if __name__ == '__main__':
    unittest.main()
