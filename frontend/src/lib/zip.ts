/** Minimal dependency-free ZIP writer (STORE method, no compression).
 *  Deterministic: fixed DOS timestamps, entries written in the order given.
 *  Sufficient for export bundles; not a general archiver. */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

const encoder = new TextEncoder();

function dosDateTime(d: Date): { date: number; time: number } {
  // Fixed to 1980-01-01 00:00 for byte-stable output regardless of when exported.
  void d;
  return { date: (1980 - 1980) << 9 | (1 << 5) | 1, time: 0 };
}

export type ZipEntry = { name: string; content: string | Uint8Array<ArrayBuffer> };

export function makeZip(entries: ZipEntry[]): Blob {
  const chunks: BlobPart[] = [];
  const central: BlobPart[] = [];
  let offset = 0;

  const u16 = (v: number): Uint8Array => new Uint8Array([v & 0xff, (v >>> 8) & 0xff]);
  const u32 = (v: number): Uint8Array => new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);

  const { date, time } = dosDateTime(new Date());

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const data = typeof entry.content === "string" ? encoder.encode(entry.content) : entry.content;
    const crc = crc32(data);

    const local = new Uint8Array(30 + nameBytes.length);
    local.set(u32(0x04034b50), 0);
    local.set(u16(20), 4); // version needed
    local.set(u16(0x0800), 6); // UTF-8 names
    local.set(u16(0), 8); // store
    local.set(u16(time), 10);
    local.set(u16(date), 12);
    local.set(u32(crc), 14);
    local.set(u32(data.length), 18);
    local.set(u32(data.length), 22);
    local.set(u16(nameBytes.length), 26);
    local.set(u16(0), 28);
    local.set(nameBytes, 30);

    chunks.push(local, data);

    const cd = new Uint8Array(46 + nameBytes.length);
    cd.set(u32(0x02014b50), 0);
    cd.set(u16(20), 4);
    cd.set(u16(20), 6);
    cd.set(u16(0x0800), 8);
    cd.set(u16(0), 10);
    cd.set(u16(time), 12);
    cd.set(u16(date), 14);
    cd.set(u32(crc), 16);
    cd.set(u32(data.length), 20);
    cd.set(u32(data.length), 24);
    cd.set(u16(nameBytes.length), 28);
    cd.set(u16(0), 30);
    cd.set(u16(0), 32);
    cd.set(u16(0), 34);
    cd.set(u16(0), 36);
    cd.set(u32(0), 38);
    cd.set(u32(offset), 42);
    cd.set(nameBytes, 46);
    central.push(cd);

    offset += local.length + data.length;
  }

  const centralSize = (central as Uint8Array[]).reduce((n, c) => n + c.length, 0);
  const end = new Uint8Array(22);
  end.set(u32(0x06054b50), 0);
  end.set(u16(0), 4);
  end.set(u16(0), 6);
  end.set(u16(entries.length), 8);
  end.set(u16(entries.length), 10);
  end.set(u32(centralSize), 12);
  end.set(u32(offset), 16);
  end.set(u16(0), 20);

  return new Blob([...chunks, ...central, end], { type: "application/zip" });
}
