import argparse
import pykd

def str_to_int(string):
    return int(string, 16)

def csvs_to_int_list(csvs):
    return [str_to_int(x) for x in csvs.split(',')]

class BadCharFinder():

    def __init__(self, addr, start, end, bad):
        self.addr = int(addr, 16)
        self.start = start
        self.end = end
        self.bad = bad
        self.new_bad = list()
        self.expected = list()
        self.results = list()

    def create_expected(self):
        self.expected = [i for i in range(self.start, self.end+1) if i not in self.bad]

    def compare(self):
        prev_bad = False
        for i in range(len(self.expected)):
            mem = pykd.loadBytes(self.addr+i, 1)[0]
            if mem == self.expected[i]:
                prev_bad = False
                continue
            if not prev_bad:
                self.new_bad.append(self.expected[i])
                prev_bad = True
                continue
            print('[+] Consecutive bad chars (data possibly truncated), aborting...')
            break

    def find(self):
        self.create_expected()
        self.compare()
    
    def __str__(self):
        if not self.new_bad: 
            return '[+] No bad characters found'
        else: 
            chars = ','.join(['0x{:02x}'.format(x) for x in self.new_bad])
            return '[+] Bad chars: {}'.format(chars) + '\n'   

def find_bad_chars(args):

    finder = BadCharFinder(
        args.addr,
        args.start,
        args.end,
        args.bad
    )
    finder.find()
    print(finder)

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'addr', 
        help='address to begin search from'
    )
    parser.add_argument(
        '-s', 
        '--start', 
        help='first byte in range to search', 
        default='00', 
        type=str_to_int
    )
    parser.add_argument(
        '-e', 
        '--end', 
        help='last byte in range to search', 
        default='ff', 
        type=str_to_int
    )
    parser.add_argument(
        '-b', 
        '--bad', 
        help='known bad characters (ex: `-b 00,0a,0d`)', 
        default = [], 
        type=csvs_to_int_list
    )
    args = parser.parse_args()

    find_bad_chars(args)

if __name__ == '__main__':
    main()
