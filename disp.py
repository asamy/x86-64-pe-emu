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
X86_EFLAGS_IOPL_MASK = 3 << 12
X86_EFLAGS_NT = 1 << 14
X86_EFLAGS_RF = 1 << 16
X86_EFLAGS_VM = 1 << 17
X86_EFLAGS_AC = 1 << 18
X86_EFLAGS_VIF = 1 << 19
X86_EFLAGS_VIP = 1 << 20
X86_EFLAGS_ID = 1 << 21

def efl_iopl(efl):
    return (efl >> 12) & 3

def dump_eflags(efl, iopl=True):
    e = ""
    if iopl:
        "iopl({:x}) ".format(efl_iopl(efl))
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

def dump_deflags(efl, prev_efl):
    eop = ""
    dif = efl ^ prev_efl
    if dif == 0:
        return eop

    if dif & X86_EFLAGS_CF:
        if efl & X86_EFLAGS_CF:
            eop = "CF=1 "
        else:
            eop = "CF=0 "
    if dif & X86_EFLAGS_PF:
        if efl & X86_EFLAGS_PF:
            eop += "PF=1 "
        else:
            eop += "PF=0 "
    if dif & X86_EFLAGS_AF:
        if efl & X86_EFLAGS_AF:
            eop += "AF=1 "
        else:
            eop += "AF=0 "
    if dif & X86_EFLAGS_ZF:
        if efl & X86_EFLAGS_ZF:
            eop += "ZF=1 "
        else:
            eop += "ZF=0 "
    if dif & X86_EFLAGS_SF:
        if efl & X86_EFLAGS_SF:
            eop += "SF=1 "
        else:
            eop += "SF=0 "
    if dif & X86_EFLAGS_TF:
        if efl & X86_EFLAGS_TF:
            eop += "TF=1 "
        else:
            eop += "TF=0 "
    if dif & X86_EFLAGS_OF:
        if efl & X86_EFLAGS_OF:
            eop += "OF=1 "
        else:
            eop += "OF=0 "
    if dif & X86_EFLAGS_NT:
        if efl & X86_EFLAGS_NT:
            eop += "NT=1 "
        else:
            eop += "NT=0 "
    if dif & X86_EFLAGS_RF:
        if efl & X86_EFLAGS_RF:
            eop += "RF=1 "
        else:
            eop += "RF=0 "
    if dif & X86_EFLAGS_VM:
        if efl & X86_EFLAGS_VM:
            eop += "VM=1 "
        else:
            eop += "VM=0 "
    if dif & X86_EFLAGS_AC:
        if efl & X86_EFLAGS_AC:
            eop += "AC=1 "
        else:
            eop += "AC=0 "
    if dif & X86_EFLAGS_VIF:
        if efl & X86_EFLAGS_VIF:
            eop += "VIF=1 "
        else:
            eop += "VIF=0 "
    if dif & X86_EFLAGS_ID:
        if efl & X86_EFLAGS_ID:
            eop += "ID=1 "
        else:
            eop += "ID=0 "
    return eop

def read_str(uc, addr):
    tmp = ""
    r = addr
    while True:
        try:
            v = uc.mem_read(r, 1)
        except:
            break
        if v == '\0' or v < 0 or v > 128:
            break
        tmp += v
        r += 1
    return tmp

def read_bytes(uc, addr, length):
    b = bytes()
    r = addr
    i = 0
    while i < length:
        try:
            v = uc.mem_read(r, 1)
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

def disp_bytes(uc, addr, length):
    buf = read_bytes(uc, addr, length)
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
