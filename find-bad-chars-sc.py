#!/usr/bin/python3

import argparse
from capstone import *
from termcolor import colored
import sys

def csvs_to_int_list(csvs):
    return [int(x, 16) for x in csvs.split(',')]

def hexstr_to_bytes(hexstr):
    vals = hexstr.split('\\x')[1:]
    ints = [int(x, 16) for x in vals]
    bytestr = [x.to_bytes(1, 'little') for x in ints]
    return b''.join(bytestr)

def format_opcodes(unformated, bad):
    final = list()
    has_color = 0
    for opcode in unformated:
        formated = '{:02x}'.format(opcode)
        if opcode in bad: 
            final.append(colored(formated, 'red'))
            has_color += 1
        else: 
            final.append(formated)
    return ' '.join(final), has_color

def disas(code, bad):

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(code, 0x1000):
        opcodes, has_color = format_opcodes(i.bytes, bad)       
        print('{} {} {}'.format(
            opcodes.ljust(24+(has_color*9), ' '), 
            i.mnemonic, 
            i.op_str
        ))

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--stdin',
        nargs=1,
        help='[*don\'t type option*] for piped shellcode, format: "\\x00\\x01" (including quotes)',
        type=argparse.FileType('r'),
        default=sys.stdin
    )
    parser.add_argument(
        '-b', 
        '--bad', 
        help='known bad characters (ex: `-b 00,0a,0d`)', 
        default=[], 
        type=csvs_to_int_list
    )
    args = parser.parse_args()
    
    code = hexstr_to_bytes(args.stdin.read()[1:-2]) # del quote & newline

    disas(code, args.bad)

if __name__ == '__main__':
    main()
