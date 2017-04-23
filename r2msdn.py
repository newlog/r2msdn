from msdn_parser import MSDNParser
import subprocess
import argparse
import r2pipe
import time
import sys
import re
import os


class R2MSDN(object):

    def __init__(self, bin_param, type_param,  verbose_param):
        self.r2 = r2pipe.open(bin_param) if bin_param else r2pipe.open()
        self.imports_struct = {}
        self.ignored_dlls = ['msvcrt']
        self.type = type_param or []
        self.verbose = verbose_param

    def execute(self):
        self.r2.cmd('aa')
        imports = self.get_imports()
        print('[r2msdn] Getting parameters for {} imported functions from MSDN. This might take a while...'.format(len(imports)))
        start = time.time()
        self.imports_struct = self.get_params_for_imports(imports)
        elapsed_time = time.time() - start
        print('[r2msdn] Parameters were found for {} imported functions in {} seconds'.format(len(self.imports_struct), round(elapsed_time, 1)))
        self.add_params_to_imports()
        return True

    def get_imports(self):
        # Ideally something like ii~!<ignored_dll>[3,9] would be executed, but r2 is broken.
        # So we execute ii~!plt[3,9] because you cannot select columns if you do not grep (looks like broken too),
        # so we grep for something we know we'll find in all lines ("plt")
        imports_out = self.r2.cmd('ii~plt[3,9]')
        return self.process_imports_output(imports_out)

    def process_imports_output(self, imports_out):
        imports_lines = imports_out.splitlines()
        imports = [self.process_imported_func(imported_func) for imported_func in imports_lines if self.prune_ignored_dlls(imported_func)]
        return imports

    @staticmethod
    def process_imported_func(imported_func):
        addr, dll_and_func = imported_func.split()
        dll, func = dll_and_func.split('.dll_', 1)  # assume a dll will not be named <something>(.dll)+.dll
        return addr, func, dll + '.dll'

    def prune_ignored_dlls(self, imported_func):
        return not any((ignore_dll.lower() in imported_func or ignore_dll.upper() in imported_func) for ignore_dll in self.ignored_dlls)

    def get_params_for_imports(self, imports):
        msdn = MSDNParser(imports, self.type, self.verbose)
        return msdn.execute()

    def add_params_to_imports(self):
        counter = 0
        # call instructions on search (/c call) do not contain address prepended 0s as in 0x00402010. So we replace them
        imports_addrs = [(re.sub('0x(0)+', '0x', addr), addr) for addr in self.imports_struct.keys()]
        calls = [(call['offset'], call['code']) for call in self.r2.cmdj('/cj call')]
        for import_addr in imports_addrs:
            for call_addr, code in calls:
                if import_addr[0] in code:
                    self.add_import_info(call_addr, self.imports_struct[import_addr[1]])
                    counter += 1
        print('[r2msdn] Imported function parameters added to {} calls'.format(counter))

    def add_import_info(self, call_addr, import_info):
        # By default only MSDN URLs will be added
        if 'imports' in self.type:
            if import_info.get('params'):  # In case import does not have parameters
                self.print_debug('[r2msdn] Parameters "{}" added to address "0x{:x}"'.format(', '.join(import_info['params']), call_addr))
                cmd = 'CC Parameters: {} @ 0x{:x}'.format(', '.join(import_info['params']), call_addr)
                self.r2.cmd(cmd)
        if 'urls' in self.type or not self.type:
            self.print_debug('[r2msdn] MSDN URL "{}" added to address "0x{:x}"'.format(import_info['search_link'], call_addr))
            cmd = 'CC MSDN URL: {} @ 0x{:x}'.format(import_info['search_link'], call_addr)
            self.r2.cmd(cmd)

    @staticmethod
    def check_requirements():
        success = True
        with open(os.devnull, 'w') as FDNULL:
            if (sys.platform in ['linux', 'linux2', 'darwin'] and subprocess.call(['which', 'phantomjs'], stdout=FDNULL, stderr=FDNULL) != 0) \
                    or (sys.platform == 'win32' and subprocess.call(['where', 'phantomjs'], stdout=FDNULL, stderr=FDNULL) != 0):
                print('[r2msdn] Requirement "phantomjs" is not found. Install NodeJS and execute: "npm -g install phantomjs-prebuilt" and set it in PATH')
                success = False
        if not success:
            print('[r2msdn] Plugin "r2msdn" will not be executed. Install requirements.')
        return success

    def print_debug(self, msg):
        if self.verbose:
            print(msg.replace('[r2msdn]', '[r2msdn] [debug] '))

class ArgUtils(object):

    @staticmethod
    def parse_arguments():
        desc = 'This radare2 plugin allows you to add the parameter names of Windows imported symbols or the URL where information about those imports can be found'
        parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('-b', '--binary', help='This argument specifies the binary to analyze. If you run the plugin inside a r2 session, this parameter should not be used')
        parser.add_argument('-t', '--type', nargs='+', help='This argument specifies what type of information will be feed to the binary. Import parameters, MSDN documentation URL or both. e.g.: (without quotes) "imports urls" or "imports" or "urls"')
        parser.add_argument('-d', '--debug', action='store_true', help='This argument specifies if debug logs should be printed')
        return parser.parse_args()


if __name__ == '__main__':
    args = ArgUtils.parse_arguments()
    bin_param = args.binary
    type_param = args.type
    verbose_param = args.debug
    try:
        r2com = R2MSDN(bin_param, type_param, verbose_param)
        if r2com.check_requirements():
            r2com.execute()
    except KeyboardInterrupt:
        print('[r2msdn] Stopping plugin execution. Changes are not rolled back.')
