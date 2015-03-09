#!/usr/bin/env python2
import sys
import capstone
from elftools.elf.elffile import ELFFile


KEYS = ["\x01\x02\x03\x04", "\x10\x20\x30\x40"]


def xoring(data, key, limit=None):
    ret = ""
    for i in xrange(0, len(data)):
        x = data[i]
        k = key[i % len(key)]
        ret += chr(ord(x) ^ ord(k))
    return ret

f = open(sys.argv[1], "rb+")
elf = ELFFile(f)
disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
text = elf.get_section_by_name(".text")
print text['sh_offset'], hex(text['sh_addr'])

symbolsENC = []

symtab = elf.get_section_by_name(".symtab")
if not symtab.is_null():
    for y in symtab.iter_symbols():
        if "ENC_" in y.name:
            symbolsENC.append(y)

for y in symbolsENC:
    print(y.name, y.entry, hex(y.entry['st_value']))
    delta = y.entry['st_value'] - text['sh_addr']
    text.stream.seek(text['sh_offset'] + delta)
    fun = text.stream.read(y.entry['st_size'])
    print "Encrypting %s..." % y.name
    for i in disassembler.disasm(fun, y.entry['st_value']):
        print hex(i.address), i.mnemonic, i.op_str
    newfun = xoring(fun, KEYS[y.entry['st_value'] % len(KEYS)])
    text.stream.seek(text['sh_offset'] + delta)
    text.stream.write(newfun)
