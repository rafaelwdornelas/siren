#!/usr/bin/env python3
"""
Generate encrypted stub blob with random key for each build.
Input: stub binary produced by objcopy from the assembled .S file.
       If the binary ends with 4 metadata quads (entry=0, code_size, patch_off,
       progress_off), those are parsed automatically.  Otherwise falls back to
       the legacy hardcoded offsets (1512 / 1508) for backwards compatibility.
Outputs a C header with the encrypted blob + fragmented key constants.
"""
import os, sys, struct

LEGACY_BLOB_PATCH    = 1512
LEGACY_BLOB_PROGRESS = 1508

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <stub.bin> <output.h>", file=sys.stderr)
        sys.exit(1)

    stub_path = sys.argv[1]
    out_path  = sys.argv[2]

    with open(stub_path, 'rb') as f:
        raw_full = f.read()

    full_size = len(raw_full)

    blob_patch    = LEGACY_BLOB_PATCH
    blob_progress = LEGACY_BLOB_PROGRESS
    raw           = raw_full

    if full_size > 32:
        entry_val, code_sz, patch_off, prog_off = struct.unpack_from('<4Q', raw_full, full_size - 32)
        if entry_val == 0 and code_sz == full_size - 32:
            raw           = raw_full[:code_sz]
            blob_patch    = patch_off
            blob_progress = prog_off
            print(f"[gen_stub] metadata: code={code_sz}B  patch={patch_off}  progress={prog_off}",
                  file=sys.stderr)

    blob_size = len(raw)

    key = os.urandom(16)

    enc = bytearray()
    for i, b in enumerate(raw):
        k = key[i % 16] ^ ((i * 7 + 3) & 0xFF)
        enc.append(b ^ k)

    k0, k1, k2, k3 = struct.unpack('<IIII', key)

    with open(out_path, 'w') as f:
        f.write("/* Auto-generated — do not edit. Regenerated each cmake configure. */\n")
        f.write(f"#ifndef SR_STUB_GEN_H\n#define SR_STUB_GEN_H\n\n")
        f.write(f"#define SR_BLOB_SIZE     {blob_size}u\n")
        f.write(f"#define SR_BLOB_ENTRY    0u\n")
        f.write(f"#define SR_BLOB_PATCH    {blob_patch}u\n")
        f.write(f"#define SR_BLOB_PROGRESS {blob_progress}u\n")
        f.write(f"#define SR_BLOB_ALIGN    4096u\n\n")

        f.write(f"/* Build configuration hashes */\n")
        f.write(f"#define SR_CFG_STACK  0x{k0:08X}u\n")
        f.write(f"#define SR_CFG_HEAP   0x{k1:08X}u\n")
        f.write(f"#define SR_CFG_ALIGN  0x{k2:08X}u\n")
        f.write(f"#define SR_CFG_FLAGS  0x{k3:08X}u\n\n")

        f.write(f"static const unsigned char sr_enc[] = {{\n")
        for i in range(0, len(enc), 12):
            chunk = enc[i:i+12]
            line = ", ".join(f"0x{b:02x}" for b in chunk)
            comma = "," if i + 12 < len(enc) else ""
            f.write(f"  {line}{comma}\n")
        f.write(f"}};\n\n")
        f.write(f"#endif /* SR_STUB_GEN_H */\n")

    dec = bytearray()
    for i, b in enumerate(enc):
        k = key[i % 16] ^ ((i * 7 + 3) & 0xFF)
        dec.append(b ^ k)
    assert dec == bytearray(raw), "Round-trip verification failed!"

if __name__ == '__main__':
    main()
