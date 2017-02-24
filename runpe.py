#!/usr/bin/env python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *

import struct
import pefile
import os
import sys
import ctypes
import string
import curses
import argparse

X86_EFLAGS_CF = 1 << 0
X86_EFLAGS_FIXED = 1 << 1
X86_EFLAGS_PF = 1 << 2
X86_EFLAGS_AF = 1 << 4
X86_EFLAGS_ZF = 1 << 6
X86_EFLAGS_SF = 1 << 7
X86_EFLAGS_TF = 1 << 8
X86_EFLAGS_IF = 1 << 9
X86_EFLAGS_DF = 1 << 10
X86_EFLAGS_OF = 1 << 11
X86_EFLAGS_IOPL = 1 << 12
X86_EFLAGS_IOPOL_MASK = 3 << 12
X86_EFLAGS_NT = 1 << 14
X86_EFLAGS_RF = 1 << 16
X86_EFLAGS_VM = 1 << 17
X86_EFLAGS_AC = 1 << 18
X86_EFLAGS_VIF = 1 << 19
X86_EFLAGS_VIP = 1 << 20
X86_EFLAGS_ID = 1 << 21

PAGE_SHIFT = 12
PAGE_SIZE = 1 << PAGE_SHIFT
PAGE_MASK = ~(PAGE_SIZE - 1)

# All of the addresses below must be page aligned.
IMAGE_BASE =  0xFFFFF88007bdb000
image_size =  0

# For IAT.
MIN_FUNC_ADDR = 0xFFFFF40010111000
MAX_FUNC_PAGES = 20
MAX_FUNC_ADDR = MIN_FUNC_ADDR + MAX_FUNC_PAGES * PAGE_SIZE
# nop
# xorl %eax, %eax
# ret
EMPTY_FUNC = '\x90\x31\xc0\xc3'
func_dict = dict()

DRIVER_BASE = 0xFFFFFA8000001000
DRIVER_SIZE = 0x1000

REGISTRY_BASE = 0xFFFFFA8000002000
REGISTRY_SIZE = 0x1000

STACK_BASE = 0xFFFFF8600000000
STACK_SIZE = 0x6000
STACK_REDZONE = 0x1000

GDT_BASE = 0xFFFFF880009FA4C0
GDT_SIZE = 0x10000
GDT_CS_IDX = 2
GDT_TR_IDX = 8
GDT_FS_IDX = 10
GDT_GS_IDX = 5
GDT_TR_BASE = 0x9f3ec0
GDT_TR_LIMIT = 0x67
GDT_FS_BASE = 0xfffffffffffb0000
GDT_FS_LIMIT = 0x7c00
GDT_GS_BASE = GDT_FS_BASE + GDT_FS_LIMIT + PAGE_SIZE
GDT_GS_LIMIT = 0xFFFFFFFF

singlestep = True
breakpoints = []
regs = [
        ("rax", UC_X86_REG_RAX),
        ("rcx", UC_X86_REG_RCX),
        ("rdx", UC_X86_REG_RDX),
        ("rbx", UC_X86_REG_RBX),
        ("rsi", UC_X86_REG_RSI),
        ("rdi", UC_X86_REG_RDI),
        ("rsp", UC_X86_REG_RSP),
        ("rbp", UC_X86_REG_RBP),
        ("r8", UC_X86_REG_R8),
        ("r9", UC_X86_REG_R9),
        ("r10", UC_X86_REG_R10),
        ("r11", UC_X86_REG_R11),
        ("r12", UC_X86_REG_R12),
        ("r13", UC_X86_REG_R13),
        ("r14", UC_X86_REG_R14),
        ("r15", UC_X86_REG_R15),
        ("rip", UC_X86_REG_RIP)
        ]

ACCESS_NONE = 0
ACCESS_READ = 1
ACCESS_WRITE = 2
ACCESS_EXEC = 4

# Curses
stdscr = None
ins_win = None
reg_win = None
stk_win = None
inf_win = None

class Breakpoint:
    def __init__(self, addr, size, access):
        self.addr = addr
        self.size = size
        self.access = access

def uc_access_to_bits(access):
    if access == UC_MEM_READ:
        return ACCESS_READ
    elif access == UC_MEM_WRITE:
        return ACCESS_WRITE
    elif access == UC_MEM_FETCH:
        return ACCESS_EXEC
    return ACCESS_NONE

def is_bp_addr(addr):
    for bp in breakpoints:
        if addr >= bp.addr and addr < bp.addr + bp.size:
            return bp
    return None

def align(a, size):
    return a & ~(size - 1)

def round_down(s, c):
    return (s / c) * c

def round_up(s, c):
    return ((s + c - 1) / c) * c

def in_range(addr, start, size):
    return addr >= start and addr < start + size

def is_stack_addr(addr):
    return in_range(addr, STACK_BASE, STACK_SIZE)

def is_redzone_addr(addr):
    return in_range(addr, STACK_BASE + STACK_SIZE - STACK_REDZONE,
            STACK_REDZONE)

def is_faked_func(addr):
    return in_range(addr, MIN_FUNC_ADDR, MAX_FUNC_ADDR)

def probe_access(mu, addr):
    try:
        mu.mem_read(addr, 1)
    except:
        return False

def read_str(mu, addr):
    tmp = ""
    r = addr
    while True:
        try:
            v = mu.mem_read(r, 1)
        except:
            break
        if v == '\0' or v < 0 or v > 128:
            break
        tmp += v
        r += 1
    return tmp

def read_bytes(mu, addr, length):
    b = bytes()
    r = addr
    i = 0
    while i < length:
        try:
            v = mu.mem_read(r, 1)
        except:
            break

        b += v
        i += 1
        r += 1
    return b

def disp_hex_ascii_line(buf, length, off):
    r = "{:05d}    ".format(off)
    for i in range(length):
        r += "{:02X} ".format(buf[i])
        if i == 7:
            r += ' '
    if length < 8:
        r += ' '

    if length < 16:
        gap = 16 - length
        for i in range(gap):
            r += "    "
    r += "    "

    for i in range(length):
        if ord(chr(buf[i])) < 128:
            r += chr(buf[i])
        else:
            r += "."
    r += "\n"
    return r

def disp_bytes(mu, addr, length):
    buf = read_bytes(mu, addr, length)
    if len(buf) == 0:
        return ""

    if len(buf) <= 16:
        return disp_hex_ascii_line(buf, len(buf), 0)

    r = ""
    off = 0
    boff = 0
    rem = len(buf)
    while True:
        line_len = 16 % rem
        r += disp_hex_ascii_line(buf[boff:boff+line_len], line_len, off)

        rem -= line_len
        boff += line_len
        off += 16
        if rem <= 16:
            r += disp_hex_ascii_line(buf[boff:boff+line_len], rem, off)
            break
    return r

def resolve_sym(addr):
    if in_range(addr, IMAGE_BASE, image_size):
        return "img+{:016X}".format(addr - IMAGE_BASE)
    if in_range(addr, DRIVER_BASE, DRIVER_SIZE):
        return "dri+{:X}".format(addr - DRIVER_BASE)
    if in_range(addr, REGISTRY_BASE, REGISTRY_SIZE):
        return "reg+{:X}".format(addr - REGISTRY_BASE)
    if is_redzone_addr(addr):
        return "red+{:X}".format(addr - STACK_BASE - (STACK_SIZE -
            STACK_REDZONE))
    if is_stack_addr(addr):
        return "stk+{:X}".format(addr - STACK_BASE)
    if in_range(addr, GDT_FS_BASE, GDT_FS_LIMIT):
        return "fs:{:X}".format(addr - GDT_FS_BASE)
    if in_range(addr, GDT_GS_BASE, GDT_GS_LIMIT):
        return "gs:{:X}".format(addr - GDT_GS_BASE)
    if is_faked_func(addr):
        fstart = align(addr, PAGE_SIZE)
        if fstart in func_dict:
            return "{:s}+{:016X}".format(func_dict[fstart], addr - fstart)
        return "unmapped-imp:{:016X}+{:X}".format(addr, addr - fstart)
    return "unk:{:X}".format(addr)

def dump_stack(mu, orig, start, count):
    for i in range(count):
        cur = start + i * 8
        val = struct.unpack("<Q", mu.mem_read(cur, 8))[0]
        out = "{:x} {:016x} => {:s}".format(cur, val, resolve_sym(val))
        string = read_str(mu, val)
        if len(string) != 0:
            out += "=> \"" + string + "\""

        c = 3
        if orig == cur:
            c = 1
        stk_win.addstr(out + "\n", curses.color_pair(c))
    stk_win.refresh()

def dump_eflags(efl):
    e = ""
    if efl & X86_EFLAGS_CF:
        e += "cf "
    if efl & X86_EFLAGS_PF:
        e += "pf "
    if efl & X86_EFLAGS_AF:
        e += "af "
    if efl & X86_EFLAGS_ZF:
        e += "zf "
    if efl & X86_EFLAGS_SF:
        e += "sf "
    if efl & X86_EFLAGS_TF:
        e += "tf "
    if efl & X86_EFLAGS_OF:
        e += "of "
    if efl & X86_EFLAGS_NT:
        e += "nt "
    if efl & X86_EFLAGS_RF:
        e += "rF "
    if efl & X86_EFLAGS_VM:
        e += "vm "
    if efl & X86_EFLAGS_AC:
        e += "ac "
    if efl & X86_EFLAGS_VIF:
        e += "vif "
    if efl & X86_EFLAGS_ID:
        e += "id"
    return e

def dump_context(mu):
    reg_win.erase()
    reg_win.addstr("Registers View\n", curses.color_pair(4))
    for reg in regs:
        regval = mu.reg_read(reg[1])
        out = "{:3s} = {:016x} *{:s}".format(reg[0], regval, resolve_sym(regval))
        string = read_str(mu, regval)
        if len(string) != 0:
            out += " = \"" + string + "\""
        reg_win.addstr(out + "\n", curses.color_pair(2))

    eflags = mu.reg_read(UC_X86_REG_EFLAGS)
    reg_win.addstr("efl = {:08x}\t{:s}".format(eflags, dump_eflags(eflags)),
            curses.color_pair(2))
    reg_win.refresh()

    rsp = mu.reg_read(UC_X86_REG_RSP)
    stk_win.erase()
    stk_win.addstr("Stack View\n", curses.color_pair(4))
    dump_stack(mu, rsp, rsp - 0x40, 5)
    dump_stack(mu, rsp, rsp, 20)

def __build_gdt_seg(base, limit, dpl, code_seg):
    # Type
    seg_type = 3
    if code_seg:
        seg_type = 0xb

    # Lower doubleword
    #       bits  0:15 = limit (0:15)
    #       bits 16:31 = base low (bits 0:15)
    slo = limit & 0xFFFF
    slo |= (base & 0xFFFF) << 16

    # Higher doubleword
    #       bits 0:7   = base mid (bits 16:23)
    #       bits 8:11  = type
    #       bit  12    = system
    #       bit  13:14 = dpl
    #       bit  15    = present
    #       bits 16:19 = limit (16:19)
    #       bit 20     = AVL
    #       bit 21     = Long mode
    #       bit 22     = D (16-bit or 32-bit)
    #       bit 23     = granuality
    #       bits 24:31 = base high (bits 24:31)
    shi = ((base >> 16) & 0xFF)
    if limit > 0xFFFFF:
        limit >>= 12
        shi |= 1 << 23
    shi |= seg_type << 8
    shi |= 1 << 12
    shi |= (dpl & 3) << 13
    shi |= 1 << 15
    shi |= ((limit >> 16) & 0xF) << 16
    shi |= 1 << 20
    shi |= 1 << 21
    shi |= ((base >> 24) & 0xFF) << 24
    return slo | shi << 32

def build_gdt_seg(base, limit, dpl, code_seg):
    return struct.pack("<QQ", __build_gdt_seg(base, limit, dpl, code_seg), (base >> 32) & 0xFFFFFFFF)

def hook_mem_unmapped(uc, access, addr, size, value, user_data):
    inf_win.addstr("{:s}: memory unmapped (r/w) at {:s} size = {:d} value = {:X}\n".format(resolve_sym(uc.reg_read(UC_X86_REG_RIP)), resolve_sym(addr), size, value))
    inf_win.refresh()
    uc.mem_map(align(addr, PAGE_SIZE), round_up(size, PAGE_SIZE))
    return True

def hook_instr_unmapped(uc, access, addr, size, value, user_data):
    inf_win.addstr("{:s}: memory unmapped (exec) {:X}\n".format(resolve_sym(uc.reg_read(UC_X86_REG_RIP)), addr))
    if is_faked_func(addr):
        inf_win.addstr("mapping fake function " + func_dict[align(addr, PAGE_SIZE)] + "\n")
        inf_win.refresh()
        uc.mem_map(align(addr, PAGE_SIZE), round_up(size, PAGE_SIZE))
        uc.mem_write(addr, EMPTY_FUNC)
        return True
    inf_win.refresh()
    return False

def hook_mem_access(uc, access, addr, size, value, user_data):
    bpa = is_bp_addr(addr)
    if bpa is not None and (bpa.access & uc_access_to_bits(access)) != 0:
        inf_win.addstr("Breakpoint hit at {:s} val = {:X}\n".format(resolve_sym(addr), value))
        inf_win.refresh()
    return True

def hook_mem_fetch(uc, access, addr, size, value, user_data):
    return True

def hook_instr(uc, address, size, user_data):
    global singlestep
    try:
        rip = uc.reg_read(UC_X86_REG_RIP)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        #md.syntax = CS_OPT_SYNTAX_ATT
        mem = uc.mem_read(address, size)
        for insn in md.disasm(mem, size):
            ins_win.addstr("{:s}: {:5s}\t{:s}\n".format(resolve_sym(rip),
                insn.mnemonic, insn.op_str), curses.color_pair(1))
        ins_win.refresh()
        dump_context(uc)
        if singlestep and inf_win.getch() == ord('g'):
            singlestep = False
            inf_win.addstr("Continue.", curses.color_pair(3))
            inf_win.refresh()
    except KeyboardInterrupt:
        uc.emu_stop()

def takeoff(filename, run_length):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # rcx = driver object
    mu.mem_map(DRIVER_BASE, DRIVER_SIZE)
    mu.reg_write(UC_X86_REG_RCX, DRIVER_BASE)

    # rdx = registry path
    mu.mem_map(REGISTRY_BASE, REGISTRY_SIZE)
    mu.reg_write(UC_X86_REG_RDX, REGISTRY_BASE)

    # allocate the stack
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - STACK_REDZONE)

    # Map GDT
    gdt = [None] * (GDT_SIZE / 16)
    gdt[GDT_FS_IDX] = build_gdt_seg(GDT_FS_BASE, GDT_FS_LIMIT, 0, 0)
    gdt[GDT_GS_IDX] = build_gdt_seg(GDT_GS_BASE, GDT_GS_LIMIT, 0, 0)
    gdt[GDT_TR_IDX] = build_gdt_seg(GDT_TR_BASE, GDT_TR_LIMIT, 0, 0)
    # Set GDTR
    gdtr = (0, GDT_BASE, GDT_SIZE, 0)
    mu.reg_write(UC_X86_REG_GDTR, gdtr)
    mu.mem_map(align(GDT_BASE, PAGE_SIZE), round_up(GDT_SIZE, PAGE_SIZE))
    mu.mem_write(GDT_BASE, bytes(gdt))
    # Map TR
    #mu.mem_map(align(GDT_TR_BASE, PAGE_SIZE), round_up(GDT_TR_LIMIT, PAGE_SIZE))

    # Set segments
    mu.reg_write(UC_X86_REG_TR, (GDT_TR_IDX << 3, GDT_TR_BASE, GDT_TR_LIMIT, 0x8b))
    mu.reg_write(UC_X86_REG_FS, GDT_FS_IDX << 3)
    mu.reg_write(UC_X86_REG_GS, GDT_GS_IDX << 3)

    # Set EFL and TPR
    mu.reg_write(UC_X86_REG_EFLAGS, X86_EFLAGS_FIXED | X86_EFLAGS_ID | X86_EFLAGS_IF)
    mu.reg_write(UC_X86_REG_CR8, 0)

    img = pefile.PE(filename)
    nt_hdr = img.NT_HEADERS
    opt = nt_hdr.OPTIONAL_HEADER
    size = opt.SizeOfImage
    base = opt.ImageBase
    ep = opt.AddressOfEntryPoint

    global image_size
    image_size = size

    inf_win.addstr("Information\n", curses.color_pair(4))
    inf_win.addstr("Image base = {:X} size = {:X}, ep = {:X} hdr_size {:X}\n".format(base,
        size, ep, opt.SizeOfHeaders))
    tmp = img.get_memory_mapped_image(ImageBase=IMAGE_BASE)
    data = bytearray(tmp)
    inf_win.addstr("Image rebased at {:X} size {:X}\n".format(IMAGE_BASE, len(tmp)))

    # Resolve IAT...
    mod_index = 0
    for module in img.DIRECTORY_ENTRY_IMPORT:
        iat_offset = 0
        for sym in module.imports:
            name = ""
            if sym.import_by_ordinal:
                if sym.name is not None:
                    name = "Ord: {:s}+{:s} ord {:d}".format(module.dll.decode("utf-8"),
                        sym.name.decode("utf-8"),
                        sym.ordinal)
                else:
                    name = "Ord: {:s} ord {:d}".format(module.dll.decode("utf-8"),
                        sym.ordinal)
            else:
                # Hint
                name = "{:s}+{:s}".format(module.dll.decode("utf-8"),
                    sym.name.decode("utf-8"))

            offset = 0
            if module.struct.FirstThunk != 0:
                offset = module.struct.FirstThunk + iat_offset
            else:
                offset = sym.struct_table.AddressOfData

            fun_addr = MIN_FUNC_ADDR + ((iat_offset >> 3) + mod_index) * PAGE_SIZE
            func_dict[fun_addr] = name
            data[offset:offset+8] = struct.pack("<Q", fun_addr)
            iat_offset += 8
            inf_win.addstr("{:s}: Fake resolve at {:X} (offset: {:X})\n".format(name, fun_addr, offset))
        mod_index += 1

    # Ok write it all.
    mu.mem_map(IMAGE_BASE, size)
    mu.mem_write(IMAGE_BASE, bytes(data))

    # Place hooks.
    mu.hook_add(UC_HOOK_CODE, hook_instr)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED,
            hook_instr_unmapped)
    mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ,
            hook_mem_access)
    mu.hook_add(UC_HOOK_MEM_FETCH,
            hook_mem_fetch)

    # Set breakpoints
    breakpoints.append(Breakpoint(IMAGE_BASE, size, ACCESS_WRITE))

    # Let it rip.
    inf_win.addstr("FIRE IN THE HOLE\n")
    inf_win.refresh()
    try:
        mu.emu_start(IMAGE_BASE + ep, min(run_length, size))
    except Exception as e:
        print("Something went wrong: ", e)

    print(">> Emulation finished, CPU context:")
    dump_context(mu)

def stop():
    curses.echo()
    curses.nocbreak()
    stdscr.keypad(False)
    curses.endwin()

def start(screen):
    global stdscr
    global reg_win, ins_win, inf_win, stk_win

    stdscr = curses.initscr()
    stdscr.keypad(True)

    ins_win = curses.newwin(20, 140, 10, 10)
    ins_win.scrollok(True)

    reg_win = curses.newwin(20, 70, 10, 80)
    reg_win.idcok(True)

    stk_win = curses.newwin(60, 160, 10, 140)
    stk_win.idcok(True)
    stk_win.idlok(False)

    inf_win = curses.newwin(100, 100, 30, 10)
    inf_win.scrollok(True)
 
    curses.echo()
    curses.cbreak()
    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="work on this file", type=str)
    parser.add_argument("--ss", help="single step mode", type=bool)
    parser.add_argument("--len", help="instructions to run", type=int)
    args = parser.parse_args()
    if args.file == None:
        print("File argument is required")
        parser.print_help()
        sys.exit(1)

    global singestep
    if args.ss != None:
        singlestep = args.ss

    length = -1
    if args.len != None:
        length = args.length

    curses.wrapper(start)
    takeoff(args.file, length)
    stop()

if __name__ == "__main__":
    main()
