#!/usr/bin/env python3
"""Extract full partition images from the aloha A/B payload OTA."""
import zipfile, struct, lzma, bz2, os, sys

OTA = 'aloha_ota_1041515800015050.zip'
OUT = 'ota_extracted'

def read_varint(buf, i):
    r = 0; s = 0
    while True:
        b = buf[i]; i += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80):
            break
        s += 7
    return r, i

def parse_fields(buf):
    i = 0; n = len(buf); out = []
    while i < n:
        tag, i = read_varint(buf, i)
        f = tag >> 3; wt = tag & 7
        if wt == 0:
            v, i = read_varint(buf, i); out.append((f, wt, v))
        elif wt == 2:
            ln, i = read_varint(buf, i); out.append((f, wt, buf[i:i+ln])); i += ln
        elif wt == 1:
            out.append((f, wt, buf[i:i+8])); i += 8
        elif wt == 5:
            out.append((f, wt, buf[i:i+4])); i += 4
        else:
            raise ValueError(f'bad wire type {wt}')
    return out

def main(names):
    z = zipfile.ZipFile(OTA)
    pf = z.open('payload.bin')
    hdr = pf.read(24)
    version, manifest_size, meta_sig_size = struct.unpack('>QQI', hdr[4:24])
    manifest = pf.read(manifest_size)
    block_size = 4096
    for f, wt, v in parse_fields(manifest):
        if f == 3 and wt == 0:
            block_size = v
    data_start = 24 + manifest_size + meta_sig_size

    parts = [v for f, wt, v in parse_fields(manifest) if f == 13]

    def get_part(name):
        for p in parts:
            fields = parse_fields(p)
            n = next((v.decode() for f, wt, v in fields if f == 1), '?')
            if n == name:
                return fields
        return None

    os.makedirs(OUT, exist_ok=True)
    for name in names:
        fields = get_part(name)
        if fields is None:
            print(f'{name}: NOT FOUND'); continue
        ops = [v for f, wt, v in fields if f == 8]
        max_end = 0
        for o in ops:
            for f, wt, v in parse_fields(o):
                if f == 6 and wt == 2:
                    ex = parse_fields(v); s = n = None
                    for f2, w2, v2 in ex:
                        if f2 == 1: s = v2
                        elif f2 == 2: n = v2
                    max_end = max(max_end, (s + n) * block_size)
        out = bytearray(max_end)
        for o in ops:
            of = parse_fields(o); d = {}; dsts = []
            for f, wt, v in of:
                if wt == 0: d[f] = v
                elif f == 6 and wt == 2:
                    ex = parse_fields(v); s = n = None
                    for f2, w2, v2 in ex:
                        if f2 == 1: s = v2
                        elif f2 == 2: n = v2
                    dsts.append((s, n))
            typ = d.get(1, 0); doff = d.get(2, 0); dlen = d.get(3, 0)
            if typ == 0:      # REPLACE
                pf.seek(data_start + doff); data = pf.read(dlen)
                for s, n in dsts:
                    seg = data[:n*block_size]
                    out[s*block_size:(s+n)*block_size] = seg; data = data[len(seg):]
            elif typ == 8:    # REPLACE_XZ
                pf.seek(data_start + doff); data = pf.read(dlen)
                dec = lzma.decompress(data)
                for s, n in dsts:
                    seg = dec[:n*block_size]
                    out[s*block_size:(s+n)*block_size] = seg; dec = dec[len(seg):]
            elif typ == 6:    # ZERO
                for s, n in dsts:
                    out[s*block_size:(s+n)*block_size] = b'\x00' * (n*block_size)
            elif typ == 1:    # REPLACE_BZ
                pf.seek(data_start + doff); data = pf.read(dlen)
                dec = bz2.decompress(data)
                for s, n in dsts:
                    seg = dec[:n*block_size]
                    out[s*block_size:(s+n)*block_size] = seg; dec = dec[len(seg):]
            else:
                print(f'  {name}: unhandled op type {typ}')
        path = os.path.join(OUT, name + '.img')
        with open(path, 'wb') as f:
            f.write(out)
        print(f'{name}: wrote {len(out)} bytes -> {path}')

if __name__ == '__main__':
    main(sys.argv[1:] if len(sys.argv) > 1 else [])
