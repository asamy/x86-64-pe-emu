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

eflag_list = [
        ( "CF", X86_EFLAGS_CF ),
        ( "PF", X86_EFLAGS_PF ),
        ( "AF", X86_EFLAGS_AF ),
        ( "ZF", X86_EFLAGS_ZF ),
        ( "SF", X86_EFLAGS_SF ),
        ( "IF", X86_EFLAGS_IF ),
        ( "TF", X86_EFLAGS_TF ),
        ( "OF", X86_EFLAGS_OF ),
        ( "NT", X86_EFLAGS_NT ),
        ( "RF", X86_EFLAGS_RF ),
        ( "VM", X86_EFLAGS_VM ),
        ( "AC", X86_EFLAGS_AC ),
        ( "VIF", X86_EFLAGS_VIF ),
        ( "ID", X86_EFLAGS_ID )
        ]

def efl_iopl(efl):
    return (efl >> 12) & 3

def dump_eflags(efl, iopl=True):
    e = ""
    if iopl:
        "iopl({:x}) ".format(efl_iopl(efl))
    for flag in eflag_list:
        if efl & flag[1]:
            e += flag[0] + " "
    return e

def dump_deflags(efl, prev_efl):
    eop = ""
    dif = efl ^ prev_efl
    if dif == 0:
        return eop

    for flag in eflag_list:
        if dif & flag[1]:
            if efl & flag[1]:
                eop += flag[0] + "=1 "
            else:
                eop += flag[0] + "=0 "
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
