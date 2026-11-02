/**
 * Magic Byte & File Signature Sniffer with CyberChef recipe recommendations.
 */

export interface MagicDetection {
  detected: boolean;
  signature: string;
  magicHex: string;
  category: "executable" | "archive" | "document" | "network" | "token" | "encoded" | "image" | "unknown";
  description: string;
  recommendedRecipe: {
    name: string;
    opIds: string[];
    description: string;
  };
}

const SIGNATURES: {
  hex: string;
  name: string;
  category: MagicDetection["category"];
  description: string;
  recipe: { name: string; opIds: string[]; description: string };
}[] = [
  {
    hex: "4d5a",
    name: "Windows PE Executable (MZ)",
    category: "executable",
    description: "Windows Portable Executable (EXE, DLL, SYS)",
    recipe: {
      name: "Extract Executable Strings",
      opIds: ["extract-ioc"],
      description: "Extract observable indicators and ASCII/Unicode strings",
    },
  },
  {
    hex: "7f454c46",
    name: "Linux ELF Binary",
    category: "executable",
    description: "Executable and Linkable Format binary for Linux",
    recipe: {
      name: "Extract ELF Strings",
      opIds: ["extract-ioc"],
      description: "Extract IOCs, paths, and symbols",
    },
  },
  {
    hex: "1f8b",
    name: "GZIP Compressed Stream",
    category: "archive",
    description: "Gzip compressed archive or HTTP response body",
    recipe: {
      name: "Decompress GZIP",
      opIds: ["gunzip"],
      description: "Decompress gzip stream to reveal plaintext content",
    },
  },
  {
    hex: "504b0304",
    name: "ZIP Archive / Office OpenXML",
    category: "archive",
    description: "ZIP archive, DOCX, XLSX, APK, or JAR package",
    recipe: {
      name: "Inspect Archive Indicators",
      opIds: ["extract-ioc"],
      description: "Scan container for embedded C2 URLs and IPs",
    },
  },
  {
    hex: "25504446",
    name: "PDF Document (%PDF)",
    category: "document",
    description: "Adobe Portable Document Format",
    recipe: {
      name: "Analyze PDF IOCs",
      opIds: ["extract-ioc", "defang"],
      description: "Extract phishing URLs and defang indicators",
    },
  },
  {
    hex: "7b5c727466",
    name: "Rich Text Format (RTF)",
    category: "document",
    description: "RTF document (often weaponized with CVE-2017-11882)",
    recipe: {
      name: "RTF Deobfuscate & Extract",
      opIds: ["extract-ioc"],
      description: "Extract embedded OLE objects and indicators",
    },
  },
  {
    hex: "d4c3b2a1",
    name: "PCAP Network Capture (LE)",
    category: "network",
    description: "Libpcap network packet capture file",
    recipe: {
      name: "Extract Network IOCs",
      opIds: ["extract-ioc"],
      description: "Harvest IP addresses and DNS domains from packet stream",
    },
  },
  {
    hex: "0a0d0d0a",
    name: "PCAPNG Network Capture",
    category: "network",
    description: "PCAP Next Generation capture file",
    recipe: {
      name: "Extract Network IOCs",
      opIds: ["extract-ioc"],
      description: "Harvest IP addresses and domains",
    },
  },
  {
    hex: "377abcaf271c",
    name: "7-Zip Archive",
    category: "archive",
    description: "7-Zip compressed container",
    recipe: {
      name: "Archive Scanner",
      opIds: ["extract-ioc"],
      description: "Scan unpacked text for IOCs",
    },
  },
];

export function detectMagicBytes(input: string): MagicDetection {
  if (!input || input.trim().length === 0) {
    return {
      detected: false,
      signature: "Empty Input",
      magicHex: "",
      category: "unknown",
      description: "No input provided",
      recommendedRecipe: { name: "No Action", opIds: [], description: "" },
    };
  }

  const trimmed = input.trim();

  // 1. Check for JWT token pattern (starts with eyJ)
  if (trimmed.startsWith("eyJ") && trimmed.includes(".")) {
    return {
      detected: true,
      signature: "JSON Web Token (JWT)",
      magicHex: "65794a...",
      category: "token",
      description: "Base64URL-encoded RFC 7519 security token",
      recommendedRecipe: {
        name: "Dissect JWT Token",
        opIds: ["jwt-dissect"],
        description: "Decode header, payload claims, and check expiration",
      },
    };
  }

  // 2. Check for PowerShell -EncodedCommand (Base64 UTF-16LE prefixes)
  // Common prefixes: cwBh, SQBu, JAB, aQBl, VwBy, SQBF, cABv
  if (/^(?:cwBh|SQBu|JAB|aQBl|VwBy|SQBF|cABv)[A-Za-z0-9+/]{8,}/.test(trimmed)) {
    return {
      detected: true,
      signature: "PowerShell UTF-16LE Base64",
      magicHex: "powershell_enc",
      category: "encoded",
      description: "PowerShell -EncodedCommand script payload",
      recommendedRecipe: {
        name: "Deobfuscate PowerShell",
        opIds: ["powershell-decode-utf16", "extract-ioc"],
        description: "Decode UTF-16LE Base64 and extract embedded URLs/IPs",
      },
    };
  }

  // 3. Hex string representation check (e.g. "4d 5a 90 00..." or "4d5a9000...")
  let hexPrefix = "";
  const hexCandidate = trimmed.replace(/[\s,:-]+/g, "");
  if (/^[0-9a-fA-F]{4,}/.test(hexCandidate)) {
    hexPrefix = hexCandidate.slice(0, 16).toLowerCase();
  } else {
    // Convert first 8 characters to hex bytes
    const encoder = new TextEncoder();
    const bytes = encoder.encode(trimmed.slice(0, 16));
    hexPrefix = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toLowerCase();
  }

  // Match against signature table
  for (const sig of SIGNATURES) {
    if (hexPrefix.startsWith(sig.hex)) {
      return {
        detected: true,
        signature: sig.name,
        magicHex: sig.hex,
        category: sig.category,
        description: sig.description,
        recommendedRecipe: sig.recipe,
      };
    }
  }

  // 4. Base64 encoded magic bytes check
  // "TVqQ" is "4D 5A 90" (PE), "H4sI" is "1F 8B 08" (GZIP), "UEsD" is "50 4B 03" (ZIP)
  if (trimmed.startsWith("TVqQ") || trimmed.startsWith("TVoA") || trimmed.startsWith("TVpB")) {
    return {
      detected: true,
      signature: "Base64-Encoded PE Executable",
      magicHex: "4d5a (b64)",
      category: "executable",
      description: "Base64 encoded Windows executable or DLL",
      recommendedRecipe: {
        name: "From Base64 to Hex / Strings",
        opIds: ["from-base64", "hexdump"],
        description: "Decode Base64 and view canonical hex dump",
      },
    };
  }

  if (trimmed.startsWith("H4sI") || trimmed.startsWith("H4sB")) {
    return {
      detected: true,
      signature: "Base64-Encoded GZIP Stream",
      magicHex: "1f8b (b64)",
      category: "archive",
      description: "Base64 encoded Gzip compressed payload",
      recommendedRecipe: {
        name: "From Base64 & Gunzip",
        opIds: ["from-base64", "gunzip"],
        description: "Decode Base64 and decompress gzip stream",
      },
    };
  }

  if (trimmed.startsWith("UEsDB")) {
    return {
      detected: true,
      signature: "Base64-Encoded ZIP Archive",
      magicHex: "504b (b64)",
      category: "archive",
      description: "Base64 encoded ZIP archive or Office OpenXML document",
      recommendedRecipe: {
        name: "From Base64 & Extract IOCs",
        opIds: ["from-base64", "extract-ioc"],
        description: "Decode Base64 and extract indicators",
      },
    };
  }

  return {
    detected: false,
    signature: "Unknown / Plaintext",
    magicHex: hexPrefix.slice(0, 8),
    category: "unknown",
    description: "No specific binary header detected",
    recommendedRecipe: {
      name: "Extract & Defang IOCs",
      opIds: ["extract-ioc", "defang"],
      description: "Scan for network observables and defang",
    },
  };
}
