#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock, call
import shlex

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'script'))


class TestWget(unittest.TestCase):
    
    def setUp(self):
        self.original_cwd = os.getcwd()
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)
        
        sys.modules['base_utils'] = MagicMock()
        sys.modules['base_utils.os'] = MagicMock()
        sys.modules['base_utils.os.cmd_util'] = MagicMock()
        sys.modules['base_utils.os.cmd_util'].CmdUtil = MagicMock()
        sys.modules['base_utils.os.cmd_util'].CmdUtil.quoteCmd = shlex.quote
        
        from upgrade_checker.utils.command import Download
        from upgrade_checker.utils.exception import ShellExecException
        self.download = Download
        self.shell_exec_exception = ShellExecException
    
    def tearDown(self):
        os.chdir(self.original_cwd)
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_invalid_inputs(self):
        """Test various invalid inputs"""
        # Test empty inputs
        with self.subTest(case="empty_url"):
            with self.assertRaises(ValueError) as context:
                self.download.wget('', 'output.txt')
            self.assertIn('url cannot be empty', str(context.exception))
        
        with self.subTest(case="empty_output"):
            with self.assertRaises(ValueError) as context:
                self.download.wget('https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker', '')
            self.assertIn('output path cannot be empty', str(context.exception))
        
        # Test invalid URL characters
        invalid_urls = [
            'http://example.com/file.txt|rm -rf /',
            'http://example.com/file.txt;cat /etc/passwd',
            'http://example.com/file.txt`whoami`',
            'http://example.com/file.txt$(id)',
            'http://example.com/file.txt\n',
        ]
        
        for url in invalid_urls:
            with self.subTest(case=f"invalid_url_chars_{url[:20]}..."):
                with self.assertRaises(ValueError) as context:
                    self.download.wget(url, 'output.txt')
                self.assertIn('url contains invalid characters', str(context.exception))
        
        # Test invalid output characters
        invalid_outputs = [
            'output.txt|rm -rf /',
            'output.txt;cat /etc/passwd',
            'output.txt`whoami`',
            'output.txt$(id)',
        ]
        
        for output in invalid_outputs:
            with self.subTest(case=f"invalid_output_chars_{output[:20]}..."):
                with self.assertRaises(ValueError) as context:
                    self.download.wget('https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker', output)
                self.assertIn('output path contains invalid characters', str(context.exception))
    
    def test_output_path_restrictions(self):
        """Test output path restrictions"""
        # Test path traversal
        path_traversal = [
            '../../../etc/passwd',
            '/etc/passwd',
            '../config',
        ]
        
        for output in path_traversal:
            with self.subTest(case=f"path_traversal_{output}"):
                with self.assertRaises(ValueError) as context:
                    self.download.wget('https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker', output)
                self.assertIn('output path is not allowed to go beyond current working directory', str(context.exception))
        
        # Test tilde expansion
        with self.subTest(case="tilde_expansion"):
            with self.assertRaises(ValueError) as context:
                self.download.wget('https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker', '~/.ssh/config')
            self.assertIn('output path contains invalid characters', str(context.exception))
    
    @patch('upgrade_checker.utils.command.Shell')
    def test_valid_operations(self, mock_shell):
        """Test valid operations"""
        mock_shell.run.return_value = (0, '')
        
        # Test valid OpenGauss OBS addresses
        valid_urls = [
            'https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker',
            'https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker/file.txt',
            'https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker/path/to/resource',
            'https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker?version=1.0&arch=x86',
        ]
        
        for url in valid_urls:
            with self.subTest(case=f"valid_url_{url.split('com')[1][:30]}..."):
                mock_shell.run.reset_mock()
                self.download.wget(url, 'output.txt')
                self.assertTrue(mock_shell.run.called)
        
        # Test valid output paths
        valid_outputs = [
            'output.txt',
            'downloads/file.txt',
            'data/archive_v1.0.tar.gz',
        ]
        
        for output in valid_outputs:
            with self.subTest(case=f"valid_output_{output}"):
                mock_shell.run.reset_mock()
                self.download.wget('https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker', output)
                self.assertTrue(mock_shell.run.called)
    
    @patch('upgrade_checker.utils.command.Shell')
    def test_exception_handling(self, mock_shell):
        """Test exception handling"""
        # Test shell exec exception cleanup
        mock_shell.run.side_effect = [
            self.shell_exec_exception('wget https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker -O output.txt', 1, 'Network error'),
            (0, '')
        ]
        
        url = 'https://opengauss.obs.cn-south-1.myhuaweicloud.com/upgrade_checker'
        output = 'output.txt'
        
        with self.assertRaises(self.shell_exec_exception):
            self.download.wget(url, output)
        
        self.assertEqual(mock_shell.run.call_count, 2)
        cleanup_cmd = mock_shell.run.call_args_list[1][0][0]
        self.assertIn('rm -rf', cleanup_cmd)
        self.assertIn('output.txt', cleanup_cmd)


if __name__ == '__main__':
    unittest.main()