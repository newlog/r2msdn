from __future__ import print_function
from selenium.common.exceptions import NoSuchElementException, WebDriverException
from selenium import webdriver
from retrying import retry
import threading
import Queue
import re
import os

# thread-safe print
_print = print
_rlock = threading.RLock()
def print(*args, **kwargs):
    with _rlock:
        _print(*args, **kwargs)


class MSDNParser(object):

    def __init__(self, imported_funcs, type_param, verbose_param):
        """

        :param imported_funcs: A list of tuples of addr, func, dll: (0x1234, CoCreateInstance, ole32.dll)
        :return (dict): Format: {addr: (func, dll, [params])}
        """
        self.imported_funcs_count = len(imported_funcs)
        self.imported_funcs = imported_funcs
        self.msdn_search_url = 'https://social.msdn.microsoft.com/search/en-US/windows?query={}%20{}&refinement=181'
        self.imports_queue = self.init_threads_queue()
        self.results = {}
        self.driver = None
        self.type_param = type_param
        self.verbose = verbose_param

    def init_threads_queue(self):
        q = Queue.Queue()
        [q.put(imported_func) for imported_func in self.imported_funcs]
        return q

    def execute(self):
        for _ in range(self.imported_funcs_count):
            thread = threading.Thread(target=self.get_imported_funcs_params)
            thread.daemon = True
            thread.start()
        self.imports_queue.join()
        return self.results

    def get_imported_funcs_params(self):
        while True:
            imported_func = self.imports_queue.get()
            self.process_imported_func(imported_func)

    def process_imported_func(self, imported_func):
        try:
            self.get_imported_func_params(imported_func)
        except NoSuchElementException:
            print('[r2msdn] Result not found for imported function "{}" from "{}"'.format(imported_func[1], imported_func[2]))
        except WebDriverInstantiationError as e:
            print(e)
        except WebDriverException as e:
            print('[r2msdn] Selenium error requesting MSDN. {}'.format(e))
            print('[r2msdn] Maybe purging current PhantomJS install and installing through NPM ("{}") might fix the issue. Make sure PhantomJS is in PATH. Check "{}"'.format('npm install phantomjs-prebuilt', 'http://stackoverflow.com/questions/36770303/phantomjs-with-selenium-unable-to-load-atom-find-element'))
        except Exception as e:
            print('[r2msdn] An unexpected error happened getting results for imported function "{}" from "{}". Error: {}'.format(imported_func[1], imported_func[2], e))
        self.imports_queue.task_done()

    def get_imported_func_params(self, imported_func):
        specific_search_url = self.msdn_search_url.format(imported_func[1], imported_func[2])
        driver = self.initialize_webdriver()
        self.request_url(driver, specific_search_url)
        search_link = self.parse_search_results(driver)
        if search_link:
            self.results[imported_func[0]] = {'function': imported_func[1], 'dll': imported_func[2], 'search_link': search_link}
            if 'imports' in self.type_param:
                self.request_url(driver, search_link)
                params_list = self.parse_parameters(driver)
                if params_list:
                    self.results[imported_func[0]]['params'] = params_list
        else:
            print('[r2msdn] Function {} for DLL {} could not be found on online MSDN'.format(imported_func[1], imported_func[2]))

    @staticmethod
    def initialize_webdriver():
        try:
            # without this lock, a connection reset by peer is thrown sometimes. The drawback is that this damn lock
            # adds about 9 seconds for only 5 imported functions.
            with _rlock:
                driver = webdriver.PhantomJS(service_log_path=os.path.devnull)
        except Exception:
            raise WebDriverInstantiationError('[r2msdn] An error occurred on Selenium  PhantomJS webdriver instantiation. You\'ll have to rerun script on a fresh r2 session')
        return driver

    @retry(wait_fixed=2000, stop_max_attempt_number=3)
    def request_url(self, driver, url):
        self.print_debug('[r2msdn] Requesting {}'.format(url))
        driver.get(url)

    @staticmethod
    def parse_search_results(driver):
        link = ''
        class_obj = driver.find_element_by_class_name('resultTitleLink')
        tmp_link = class_obj.get_attribute('href')
        if tmp_link.startswith('https://msdn.microsoft.com/en-us/library/windows/desktop/'):
            link = tmp_link
        return link

    @classmethod
    def parse_parameters(cls, driver):
        class_obj = driver.find_element_by_class_name('codeSnippetContainerCode')
        code_snippet = class_obj.find_element_by_css_selector('div pre').text
        return cls.parse_code_snippet_params(code_snippet)

    @staticmethod
    def parse_code_snippet_params(code_snippet):
        lines = code_snippet.splitlines()
        params = lines[1:len(lines)-1]
        return [re.sub(' +', ' ', param).strip().replace(',', '') for param in params]

    def print_debug(self, msg):
        if self.verbose:
            print(msg.replace('[r2msdn]', '[r2msdn] [debug] '))


class WebDriverInstantiationError(Exception):
    pass
