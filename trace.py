from capstone import *
from capstone.x86 import *
from disp import *

import numpy as np
import os

INSN_UNK = 0
INSN_JMP_CONDITIONAL = 1
INSN_JMP_UNCONDITIONAL = 2
INSN_JMP_DYN = 3
INSN_CALL = 4
INSN_CALL_DYN = 5
INSN_NOP = 6
INSN_UD2 = 7
INSN_FP_SAVE = 8
INSN_FP_SETUP = 9
INSN_RET = 10
INSN_IRETF = 11

class Instruction:
    def __init__(self, insn, addr):
        self.insn = insn
        self.outs = ""
        self.outp = 0xdeadbeefdeadbeef
        self.addr = addr
        self.type = INSN_UNK
        self.call = False
        self.labl = False
        self.calc = 0
        self.cache()

    def __repr__(self):
        i = self.insn
        return "{:5s}\t{:s}".format(i.mnemonic, i.op_str)

    def process(self, mu, prev_efl):
        insn = self.insn
        outp = None
        if len(insn.operands) != 0:
            out = insn.operands[0]
            mask = 0xffffffffffffffff
            if out.size == 1:
                mask = 0xff
            elif out.size == 2:
                mask = 0xffff
            elif out.size == 4:
                mask = 0xffffffff

            if "push" in insn.mnemonic or "pop" in insn.mnemonic:
                self.outs = "RSP = {:X}".format(mu.reg_read(X86_REG_RSP))
            elif out.type == X86_OP_REG:
                outp = mu.reg_read(out.reg) & mask
                self.outs = "{:3s} = {:X}".format(insn.reg_name(out.reg).upper(), outp)
            elif out.type == X86_OP_IMM:
                outp = out.imm & mask
            """
            elif out.type == X86_OP_MEM:
                mem = out.mem
                tmp = mu.mem_read(mem.base + mem.disp + mem.index * mem.scale, out.size)
                out = struct.unpack("<Q", tmp)[0]
                outp = out & mask
            """
        efl = mu.reg_read(X86_REG_EFLAGS)
        if (efl ^ prev_efl) != 0:
            self.outs += " " + dump_deflags(efl, prev_efl)
        self.outp = outp

        if self.type >= INSN_JMP_CONDITIONAL and self.type <= INSN_JMP_DYN:
            return (outp, False)
        elif self.type == INSN_CALL or self.type == INSN_CALL_DYN:
            return (outp, True)
        return None

    def cache(self):
        insn = self.insn
        op1 = insn.opcode[0]
        op2 = insn.opcode[1]
        rex = insn.rex
        modrm = insn.modrm
        sib = insn.sib

        if (op1 >= 0x70 and op1 <= 0x7f) or op1 == 0xe3:
            self.type = INSN_JMP_CONDITIONAL
        elif op1 == 0x0f:
            if op2 >= 0x80 and op2 <= 0x8f:
                self.type = INSN_JMP_CONDITIONAL
            elif op2 == 0x0b or op2 == 0xb9:
                self.type = INSN_UD2
            elif op2 == 0x0d or op2 == 0x1f:
                self.type = INSN_NOP
        elif op1 == 0x89:
            if rex == 0x48 and modrm == 0xe5:
                self.type == INSN_FP_SAVE
        elif op1 == 0x8b:
            if rex == 0x48 and modrm == 0x2c and sib == 0x24:
                self.type == INSN_FP_SETUP
        elif op1 == 0x90:
            self.type = INSN_NOP
        elif op1 == 0xe9 or op1 == 0xeb:
            self.type = INSN_JMP_UNCONDITIONAL
        elif op1 == 0xc2 or op1 == 0xc3:
            self.type = INSN_RET
        elif op1 == 0xca or op1 == 0xcb or op1 == 0xcf:
            self.type = INSN_IRETF
        elif op1 == 0xe8:
            self.type = INSN_CALL
        elif op1 == 0xff:
            r = (modrm >> 3) & 7
            if r == 2 or r == 3:
                self.type = INSN_CALL_DYN
            elif r == 4:
                self.type = INSN_JMP_DYN

class Trace:
    def __init__(self):
        self.insn_stack = []
        self.prev_efl = 0

    def push_insn(self, mu, addr, insn):
        l = len(self.insn_stack)
        out = None
        if l != 0:
            top = self.insn_stack[l - 1]
            out = top.process(mu, self.prev_efl)
            self.prev_efl = mu.reg_read(X86_REG_EFLAGS)
        else:
            # First instruction, cache EFL.
            self.prev_efl = mu.reg_read(X86_REG_EFLAGS)

        i = Instruction(insn, addr)
        self.insn_stack.append(i)
        if out is not None:
            # top is definitely a jmp or call, but it could be unconditional so we need to
            # check the addr.
            top.calc = np.uint64(top.addr) + np.uint64(out[0]) - np.uint64(top.insn.size)
            if addr == top.calc:
                i.calc = 0xee
                if out[1]:
                    i.call = True
                else:
                    i.labl = True

    def write(self, path):
        self.wr_trace(path)
        self.wr_flow(path)

    def wr_trace(self, path):
        f = os.open(path, os.O_CREAT | os.O_RDWR)
        os.write(f, "Address\t\t\tInstruction\t\t\t\tResult\n")
        for insn in self.insn_stack:
            addr = "{:016x}".format(insn.addr)
            if insn.call:
                addr = "sub_" + addr
            elif insn.labl:
                addr = "loc_" + addr

            os.write(f, addr + "\t{:36s}\t{:50s}\n".format(insn, insn.outs))
        os.close(f)

    def wr_flow(self, path):
        f = os.open("flow" + path, os.O_CREAT | os.O_RDWR)
        for insn in self.insn_stack:
            if insn.call:
                os.write(f, "sub_{:x}:\n".format(insn.addr))
            elif insn.labl:
                os.write(f, "loc_{:x}:\n".format(insn.addr))
            os.write(f, "\t{:s}\n".format(insn))
        os.close(f)

