import os
import struct

def check_dll(path):
    try:
        with open(path, 'rb') as f:
            f.seek(0x3c)
            pe_off_bytes = f.read(4)
            if len(pe_off_bytes) < 4: return "Invalid"
            pe_off = struct.unpack('<I', pe_off_bytes)[0]
            f.seek(pe_off + 4)
            machine_bytes = f.read(2)
            if len(machine_bytes) < 2: return "Invalid"
            machine = struct.unpack('<H', machine_bytes)[0]
            return f"{hex(machine)}"
    except Exception as e:
        return str(e)

def _rva_to_offset(pe, rva):
    pe_off = struct.unpack('<I', pe[0x3C:0x40])[0]
    num_sections = struct.unpack('<H', pe[pe_off + 6:pe_off + 8])[0]
    opt_hdr_sz = struct.unpack('<H', pe[pe_off + 20:pe_off + 22])[0]
    sect_hdr_off = pe_off + 24 + opt_hdr_sz
    for i in range(num_sections):
        s_off = sect_hdr_off + (i * 40)
        v_sz = struct.unpack('<I', pe[s_off + 8:s_off + 12])[0]
        v_addr = struct.unpack('<I', pe[s_off + 12:s_off + 16])[0]
        r_sz = struct.unpack('<I', pe[s_off + 16:s_off + 20])[0]
        r_ptr = struct.unpack('<I', pe[s_off + 20:s_off + 24])[0]
        if v_addr <= rva < v_addr + max(v_sz, r_sz):
            return rva - v_addr + r_ptr
    return None

def _read_c_string(pe, off):
    end = off
    while end < len(pe) and pe[end] != 0:
        end += 1
    return pe[off:end].decode("ascii", errors="ignore")

def get_imports(path):
    with open(path, 'rb') as f:
        pe = f.read()
    if pe[:2] != b"MZ": return []
    pe_off = struct.unpack('<I', pe[0x3C:0x40])[0]
    magic = struct.unpack('<H', pe[pe_off+24:pe_off+26])[0]
    dd_off = pe_off + 24 + (96 if magic == 0x10B else 112)
    imp_rva = struct.unpack('<I', pe[dd_off+8:dd_off+12])[0]
    imp_sz = struct.unpack('<I', pe[dd_off+12:dd_off+16])[0]
    if imp_rva == 0: return []
    imp_off = _rva_to_offset(pe, imp_rva)
    if imp_off is None: return []
    
    imports = []
    cur = imp_off
    while cur + 20 <= len(pe):
        name_rva = struct.unpack('<I', pe[cur+12:cur+16])[0]
        if name_rva == 0: break
        name_off = _rva_to_offset(pe, name_rva)
        if name_off:
            imports.append(_read_c_string(pe, name_off))
        cur += 20
    return imports

sdk_dir = r'app\sdk'
for d in ['libzkfp.dll', 'fpslib.dll', 'ZKFPCap.dll']:
    p = os.path.join(sdk_dir, d)
    if os.path.exists(p):
        print(f"Imports for {p}:")
        for imp in get_imports(p):
            print(f"  {imp}")
