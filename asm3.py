import sys
from collections import defaultdict


# 'cmd': ((1st arg type, 2nd arg type, ...), can be indirect?, parameters)
KEYWORDS = {'nop': ((), False, {'src': 'gp', 'dst': 'gp'}),
            'mov': (('dst', 'src'), True, {}),
            'out': (('src',), True, {'dst': 'out'}),
            'ss': (('src',), True, {'dst': 'sp'}),
            'push': (('src',), False, {'stack': 'push', 'dst_ind': True, 'dst': 'sp'}),
            'pop': (('dst',), False, {'stack': 'pop', 'src_ind': True, 'src': 'sp'}),
            'add': (('src',), True, {'alu': 'add', 'dst': 'acc'}),
            'sub': (('src',), True, {'alu': 'sub', 'dst': 'acc'}),
            'subr': (('src',), True, {'alu': 'subr', 'dst': 'acc'}),
            'mul': (('src',), True, {'alu': 'mul', 'dst': 'acc'}),
            'div': (('src',), True, {'alu': 'div', 'dst': 'acc'}),
            'mod': (('src',), True, {'alu': 'mod', 'dst': 'acc'}),
            'divr': (('src',), True, {'alu': 'divr', 'dst': 'acc'}),
            'modr': (('src',), True, {'alu': 'modr', 'dst': 'acc'}),
            'shl': (('src',), True, {'alu': 'shl', 'dst': 'acc'}),
            'shr': (('src',), True, {'alu': 'shr', 'dst': 'acc'}),
            'rol': (('src',), True, {'alu': 'rol', 'dst': 'acc'}),
            'ror': (('src',), True, {'alu': 'ror', 'dst': 'acc'}),
            'and': (('src',), True, {'alu': 'and', 'dst': 'acc'}),
            'or': (('src',), True, {'alu': 'or', 'dst': 'acc'}),
            'xor': (('src',), True, {'alu': 'xor', 'dst': 'acc'}),
            'not': ((), False, {'alu': 'not', 'src': 'acc', 'dst': 'acc'}),
            'padd': ((), False, {'stack': 'pop', 'alu': 'add', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'psub': ((), False, {'stack': 'pop', 'alu': 'sub', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'psubr': ((), False, {'stack': 'pop', 'alu': 'subr', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pmul': ((), False, {'stack': 'pop', 'alu': 'mul', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pdiv': ((), False, {'stack': 'pop', 'alu': 'div', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pmod': ((), False, {'stack': 'pop', 'alu': 'mod', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pdivr': ((), False, {'stack': 'pop', 'alu': 'divr', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pmodr': ((), False, {'stack': 'pop', 'alu': 'modr', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pshl': ((), False, {'stack': 'pop', 'alu': 'shl', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pshr': ((), False, {'stack': 'pop', 'alu': 'shr', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'prol': ((), False, {'stack': 'pop', 'alu': 'rol', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pror': ((), False, {'stack': 'pop', 'alu': 'ror', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pand': ((), False, {'stack': 'pop', 'alu': 'and', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'por': ((), False, {'stack': 'pop', 'alu': 'or', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'pxor': ((), False, {'stack': 'pop', 'alu': 'xor', 'src_ind': True, 'src': 'sp', 'dst': 'acc'}),
            'jmp': (('src',), True, {'dst': 'pc'}),
            'jz': (('src',), True, {'dst': 'pc', 'cond': 'acc==0'}),
            'jnz': (('src',), True, {'dst': 'pc', 'cond': 'acc!=0'}),
            'jeq': (('src',), True, {'dst': 'pc', 'cond': 'acc==gp'}),
            'jne': (('src',), True, {'dst': 'pc', 'cond': 'acc!=gp'}),
            'jin': (('src',), True, {'dst': 'pc', 'cond': 'in-port'}),
            'incsp': ((), False, {'stack': 'push', 'src': 'gp', 'dst': 'gp'}),
            'decsp': ((), False, {'stack': 'pop', 'src': 'gp', 'dst': 'gp'}),
            'ret': ((), False, {'stack': 'pop', 'src_ind': True, 'src': 'sp', 'dst': 'pc', 'add_3': True})}

ALU_OP = {'add': 0,
          'sub': 1,
          'subr': 2,
          'mul': 3,
          'div': 4,
          'mod': 5,
          'divr': 6,
          'modr': 7,
          'shl': 8,
          'shr': 9,
          'rol': 10,
          'ror': 11,
          'and': 12,
          'or': 13,
          'xor': 14,
          'not': 15}

CONDITION = {'acc==0': 0,
             'acc!=0': 2,
             'acc==gp': 4,
             'acc!=gp': 6,
             'in-port': 1}

SRC = {'in': 0,
       'out': 1,
       'acc': 2,
       'ax': 2,
       'gp': 3,
       'bx': 3,
       'ram': 4,
       'pc': 5,
       'lit': 6}

DST = {'sp': 0,
       'acc': 1,
       'ax': 1,
       'gp': 2,
       'bx': 2,
       'pc': 3,
       'out': 4}

ADDR = {'in': 0,
        'sp': 1,
        'acc': 2,
        'ax': 2,
        'gp': 3,
        'bx': 3,
        'pc': 4,
        'lit': 5}


BUILTIN_MACROS = '''
#macro call addr
    push pc
    jmp addr
#end
'''


class Instruction:
    def __init__(self, args):
        self.has_operand = False
        self.alu = ''
        self.stack = ''
        self.add_3 = False
        self.cond = ''
        self.src_ind = False
        self.dst_ind = False
        self.src = ''
        self.dst = ''
        self.operand = 0

        if args:
            for arg in args:
                setattr(self, arg, args[arg])

        if self.src == 'lit' or self.dst == 'lit':
            self.has_operand = True

    def __repr__(self):
        return repr(self.__dict__)

    def pack(self):
        inst = [
            (
                (self.has_operand << 7) +
                (bool(self.alu) << 6) +
                (bool(self.stack) << 5) +
                (bool(self.stack == 'pop' or self.cond) << 4)
            ), (
                (self.src_ind << 7) +
                (self.dst_ind << 6)
            )
        ]

        if self.alu:
            inst[0] += ALU_OP[self.alu]
        else:
            inst[0] += self.add_3 << 3
            if self.cond:
                inst[0] += CONDITION[self.cond]

        if self.src_ind:
            if self.src not in ADDR:
                raise Exception('Illegal indirect source: {}'.format(self.src))
            inst[1] += ADDR[self.src] << 3
        else:
            if self.src not in SRC:
                raise Exception('Illegal source: {}'.format(self.src))
            inst[1] += SRC[self.src] << 3

        if self.dst_ind:
            if self.dst not in ADDR:
                raise Exception('Illegal indirect destination: {}'.format(self.dst))
            inst[1] += ADDR[self.dst]
        else:
            if self.dst not in DST:
                raise Exception('Illegal destination: {}'.format(self.dst))
            inst[1] += DST[self.dst]

        if self.has_operand:
            inst.append(int.from_bytes(self.operand, 'big'))

        return bytes(inst)


def bin_fmt(binary):
    return ' '.join('{:02x}'.format(b) for b in binary)


def sanitize_line(line):
    comment = line.find('//')
    if comment != -1:
        line = line[:comment]

    return line.strip()


def parse_literal(val):
    return int(val, 0).to_bytes(1, 'big')


def parse_variable_value(val):
    if val.startswith('"'):
        return eval('b' + val[:-1] + r'\0"')

    return parse_literal(val)


def parse_arg(arg, type):
    ind = False
    if arg.startswith('[') and arg.endswith(']'):
        ind = True
        arg = arg[1:-1]

    if arg[0].isdigit():
        return {type + '_ind': ind, type: 'lit', 'operand': parse_literal(arg)}
    else:
        return {type + '_ind': ind, type: arg}


def preprocess_macro_definitions(code):
    # TODO: Make sure there are no cyclic dependencies
    macro_name = ''
    macro_code = ''
    macro_params = {}
    macros = {}
    for line in code.splitlines():
        words = line.split()
        if not words:
            continue
        cmd = words.pop(0)
        if cmd == '#macro':
            macro_name = words.pop(0)
            macro_params = {w: '%{}'.format(n) for n, w in enumerate(words)}
            macro_code = ''
        elif cmd == '#end':
            for param, symbol in macro_params.items():
                macro_code = macro_code.replace(param, symbol)
            macros[macro_name] = (macro_code, len(macro_params))
        elif macro_name:
            macro_code += line.strip() + '\n'
    return macros


def preprocess(code, macros):
    finished = False
    while not finished:
        finished = True
        out = ''
        for n, line in enumerate(code.splitlines()):
            words = line.replace(',', ' ').split()
            if not words:
                out += '\n'
                continue
            cmd = words.pop(0)
            if cmd in macros:
                finished = False
                macro_code, macro_args = macros[cmd]
                if len(words) != macro_args:
                    raise Exception('Error in line {}: Macro {} takes {} argument(s), {} given'.format(n, cmd, macro_args, len(words)))
                for n, arg in enumerate(words):
                    macro_code = macro_code.replace('%{}'.format(n), arg)
                out += macro_code
            else:
                out += line.strip() + '\n'
        code = out
    return out


def compile(code):
    out = bytearray()
    symbols = defaultdict(lambda: [None, []])  # 'name': (offset, [(usage_offset, is_minus_3), ...])

    for n, line in enumerate(code.splitlines()):
        line = sanitize_line(line)

        words = line.replace(',', ' ').split()
        if not words:
            continue

        cmd = words.pop(0)
        if cmd.endswith(':'):
            symbols[cmd[:-1]][0] = len(out)
            if words:
                out += b'\0' * parse_literal(words[0])

        elif cmd.startswith('[') and cmd.endswith(']'):
            out += b'\0' * parse_literal(cmd[1:-1])

        elif cmd.startswith('$'):
            var = cmd[1:]
            if not words:
                raise Exception('Error in line {}: No value for variable {}'.format(n, var))

            try:
                val = parse_variable_value(line.split(None, 1)[1])
            except:
                raise Exception('Error in line {}: Illegal value for variable {}'.format(n, var))

            symbols[var][0] = len(out)

            out += val

        else:
            if cmd not in KEYWORDS:
                raise Exception('Error in line {}: Unknown command: {}'.format(n, cmd))
            cmd_params = {}
            cmd_params.update(KEYWORDS[cmd][2])
            for arg, type in zip(words, KEYWORDS[cmd][0]):
                if arg.startswith(':'):
                    symbols[arg[1:]][1].append((len(out) + 2, False))
                    cmd_params.update(parse_arg('0', type))

                elif arg.startswith(';'):
                    symbols[arg[1:]][1].append((len(out) + 2, True))
                    cmd_params.update(parse_arg('0', type))

                elif arg.startswith('$'):
                    symbols[arg[1:]][1].append((len(out) + 2, False))
                    cmd_params.update(parse_arg('[0]', type))

                else:
                    cmd_params.update(parse_arg(arg, type))

            try:
                out += Instruction(cmd_params).pack()
            except Exception as e:
                raise Exception('Error in line {}: {}'.format(n, e))

    print('Symbols:')
    for label, (offset, _refs) in symbols.items():
        print('{:<12}: 0x{:02x} ({})'.format(label, offset, offset))
    print()
    print('Size of code: {} bytes'.format(len(out)))
    return (out, dict(symbols))


def link(code, symbols):
    out = list(code)
    for _symbol, (offset, refs) in symbols.items():
        for ref in refs:
            out[ref[0]] = offset - ref[1] * 3
    return bytes(out)


def write_ram_file(binary, filename):
    with open(filename, 'w') as f:
        f.write('v2.0 raw\n' + bin_fmt(binary))


def pretty_print_code(code, binary):
    print()
    print('Disassembly')
    print('===========')
    pc = 0
    for n, line in enumerate(code.splitlines()):
        line = sanitize_line(line)
        if not line:
            continue

        print('0x{:02X} {:>3}: {:<32}'.format(pc, n, line), end='')

        words = line.split(None, 1)
        cmd = words.pop(0)
        if cmd.startswith('$'):
            oplen = len(parse_variable_value(line.split(None, 1)[1]))
        elif cmd in KEYWORDS:
            oplen = 2 + ((binary[pc] & 0x80) >> 7)
        else:
            oplen = 0

        print(bin_fmt(binary[pc: pc + oplen]))
        pc += oplen


def main():
    with open(sys.argv[1]) as f:
        code = f.read()

    try:
        macros = preprocess_macro_definitions(BUILTIN_MACROS)
        code = preprocess(code, macros)
        object, symbols = compile(code)
        binary = link(object, symbols)
        write_ram_file(binary, sys.argv[2])
        pretty_print_code(code, binary)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()