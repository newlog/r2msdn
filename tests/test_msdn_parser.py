from msdn_parser import MSDNParser
from selenium import webdriver
import unittest
import os


class TestMSDNParsing(unittest.TestCase):

  def test_get_and_parse_html(self):
      self.maxDiff = None
      expected_results = {'0x000000': {'function': 'CoCreateInstance', 'dll': 'ole32.dll', 'params': ['_In_ REFCLSID rclsid', '_In_ LPUNKNOWN pUnkOuter', '_In_ DWORD dwClsContext', '_In_ REFIID riid', '_Out_ LPVOID *ppv'], 'search_link': 'https://msdn.microsoft.com/en-us/library/windows/desktop/ms686615(v=vs.85).aspx'}}
      msdn = MSDNParser([('0x000000', 'CoCreateInstance', 'ole32.dll')], ['imports', 'urls'], False)
      results = msdn.execute()
      self.assertEqual(results, expected_results)

  def test_parse_html(self):
      expected_link = 'https://msdn.microsoft.com/en-us/library/windows/desktop/ms686615(v=vs.85).aspx'
      func, dll = 'CoCreateInstance', 'ole32.dll'
      msdn = MSDNParser([('0x000000', 'CoCreateInstance', 'ole32.dll')], ['imports', 'urls'], False)
      driver = webdriver.PhantomJS(service_log_path=os.path.devnull)
      driver.get(msdn.msdn_search_url.format(func, dll))
      search_link = msdn.parse_search_results(driver)
      self.assertEqual(search_link, expected_link)
