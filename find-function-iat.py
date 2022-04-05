import argparse
import pykd 
import sys

class AddrResolver():

    def __init__(self, module, func):
        self.module = module
        self.func = func
        self.image_base = pykd.module(self.module).begin()
        self.iat_offset = int()
        self.iat_size = int()
        self.entries = dict()
        self.alt_entry = str()
        self.va_resolved = int()

    def find_lines_containing(self, lines, string):
        result = list()
        for line in lines:
            if string in line:
                result.append(line)
        return result

    def get_iat_info(self):
        result = pykd.dbgCommand('!dh {} -f'.format(self.module))
        line = self.find_lines_containing(result.splitlines(), 'Import Address Table Directory')[0]
        self.iat_offset = int(line[:8], 16)
        self.iat_size = int(line[10:18], 16)

    def proc_iat_entries(self, entries):
        processed = dict()
        for entry in entries:
            processed[entry[2]] = {
                'iat': int(entry[0], 16),
                'resolved': int(entry[1], 16)
            }
        return processed

    def get_kernel32_iat_entries(self):
        result = pykd.dbgCommand('dps {} {}'.format(
            hex(self.image_base + self.iat_offset), # start
            hex(self.image_base + self.iat_offset + self.iat_size)) # end
        )
        lines = self.find_lines_containing(result.splitlines(), 'KERNEL32!')
        self.entries = self.proc_iat_entries([line.split() for line in lines])
    
    def try_get_func(self):
        va = 'KERNEL32!{}'.format(self.func)
        if va in self.entries:
            print('[+] {} ({} IAT entry)'.format(hex(self.entries[va]['iat']), self.func))
            exit(0) 

    def get_last_entry(self): 
        self.alt_entry = list(self.entries.keys())[-1]

    def get_resolved(self):
        self.va_resolved = int(pykd.dbgCommand('x KERNEL32!{}'.format(self.func))[:8], 16)
    
    def resolve(self):

        self.get_iat_info()
        self.get_kernel32_iat_entries()
        self.try_get_func()
        self.get_last_entry()
        self.get_resolved()
    
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'module', 
        help='address to begin search from'
    )
    parser.add_argument(
        'func',
        choices=['VirtualAllocStub', 'WriteProcessMemoryStub', 'VirtualProtectStub']
    )
    args = parser.parse_args()

    resolver = AddrResolver(args.module, args.func)
    resolver.resolve()
    
    diff = resolver.va_resolved - resolver.entries[resolver.alt_entry]['resolved']
    neg = (0xffffffffffffffff - abs(diff) + 1) & 0xffffffff

    print('[-] Using {} (couldn\'t find {} IAT address)'.format(resolver.alt_entry, args.func))
    print('[+] {} ({} IAT entry)'.format(hex(resolver.entries[resolver.alt_entry]['iat']), resolver.alt_entry[9:]))
    print('[+] {} ({} resolved)'.format(hex(resolver.entries[resolver.alt_entry]['resolved']), resolver.alt_entry[9:]))
    print('[+] {} ({} resolved)'.format(args.func, hex(resolver.va_resolved)))
    print('[+] {} (offset = {} - {})'.format(hex(diff), args.func, resolver.alt_entry[9:]))
    print('[+] {} (negative)'.format(hex(neg)))

if __name__ == '__main__':
    main()
