#!/usr/bin/env python2
import sys
import capstone
from elftools.elf.elffile import ELFFile
import logging
import struct

txtblk = '\033[0;30m'  # Nero - Regular
txtred = '\033[0;31m'  # Rosso
txtgrn = '\033[0;32m'  # Verde
txtylw = '\033[0;33m'  # Giallo
txtblu = '\033[0;34m'  # Blu
txtpur = '\033[0;35m'  # Viola
txtcyn = '\033[0;36m'  # Ciano
txtwht = '\033[0;37m'  # Bianco
bldblk = '\033[1;30m'  # Nero - Bold
bldred = '\033[1;31m'  # Rosso
bldgrn = '\033[1;32m'  # Verde
bldylw = '\033[1;33m'  # Giallo
bldblu = '\033[1;34m'  # Blu
bldpur = '\033[1;35m'  # Viola
bldcyn = '\033[1;36m'  # Ciano
bldwht = '\033[1;37m'  # Bianco
unkblk = '\033[4;30m'  # Nero - Underline
undred = '\033[4;31m'  # Rosso
undgrn = '\033[4;32m'  # Verde
undylw = '\033[4;33m'  # Giallo
undblu = '\033[4;34m'  # Blu
undpur = '\033[4;35m'  # Viola
undcyn = '\033[4;36m'  # Ciano
undwht = '\033[4;37m'  # Bianco
bakblk = '\033[40m'   # Nero - Background
bakred = '\033[41m'   # Rosso
badgrn = '\033[42m'   # Verde
bakylw = '\033[43m'   # Giallo
bakblu = '\033[44m'   # Blu
bakpur = '\033[45m'   # Viola
bakcyn = '\033[46m'   # Ciano
bakwht = '\033[47m'   # Bianco
txtrst = '\033[0m'    # Text Reset


logging.basicConfig(
    format=txtylw + '%(asctime)s' + txtblu + ' %(message)s' + txtrst,
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.DEBUG)


KEYS = ["\x01\x02\x03\x04", "\x10\x20\x30\x40",
        "B00B", "DEAD", "\xff\xff\xff\xff"]


def xoring(data, key, limit=None):
    ret = ""
    if limit is None:
        limit = len(data)
    for i in xrange(0, limit):
        x = data[i]
        k = key[i % len(key)]
        ret += chr(ord(x) ^ ord(k))
    return ret

f = open(sys.argv[1], "rb+")
elf = ELFFile(f)
disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
text = elf.get_section_by_name(".text")
logging.debug("%d %s" % (text['sh_offset'], hex(text['sh_addr'])))

symbolsENC = dict()

symtab = elf.get_section_by_name(".symtab")
if not symtab.is_null():
    for y in symtab.iter_symbols():
        if "ENC_" in y.name:
            key = struct.pack("<I", y.entry['st_value'])
            logging.debug("%s key is %s" % (y.name, key.encode("hex")))
            symbolsENC[key] = {"name": y.name,
                               "st_value": y.entry['st_value'], "st_size": y.entry["st_size"]}


TOPATCH = "\x68\x00\xFA\x0F\xF0\x68"
text.stream.seek(0)
binary = text.stream.read()
for k in symbolsENC:
    y = symbolsENC[k]
    pos = binary.find(TOPATCH + k)
    if pos > 0:
        print pos, y['st_size'] // 4
        text.stream.seek(pos)
        newpush = "\x68" + struct.pack("<I", y['st_size'] // 4)
        text.stream.write(newpush)
        logging.debug(("Patched " + bldgrn + "%s" + txtblu +
                       " in pos %d with %s") % (y['name'], pos, newpush.encode("hex")))
    else:
        logging.debug(
            ("Function not found " + bldred + "%s" + txtblu) % y['name'])

for k in symbolsENC:
    y = symbolsENC[k]
    logging.debug("%s %s" % (y["name"], hex(y['st_value'])))
    delta = y['st_value'] - text['sh_addr']
    text.stream.seek(text['sh_offset'] + delta)
    fun = text.stream.read(y['st_size'])
    logging.info(("Encrypting " + bldylw + "%s..." + txtrst) % y["name"])
    # for i in disassembler.disasm(fun, y['st_value']):
    #     logging.debug(("%s " + bldgrn + "%s %s" + txtrst) %
    #                   (hex(i.address), i.mnemonic, i.op_str))
    newfun = xoring(fun, KEYS[y['st_value'] % len(KEYS)], limit=(y['st_size'] // 4) * 4)
    text.stream.seek(text['sh_offset'] + delta)
    text.stream.write(newfun)
