import { useState, useRef, useCallback } from "react";
import { analyzeMetadata } from "./metadataDumper.js";

// ─── ELF Parser ──────────────────────────────────────────────────────────────
function parseELFSymbols(buffer) {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);

  // Check ELF magic
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    throw new Error("Not a valid ELF file");
  }

  const is64 = bytes[4] === 2;
  const isLE = bytes[5] === 1;

  const r16 = (o) => isLE ? view.getUint16(o, true) : view.getUint16(o, false);
  const r32 = (o) => isLE ? view.getUint32(o, true) : view.getUint32(o, false);
  const r64 = (o) => {
    const lo = isLE ? view.getUint32(o, true) : view.getUint32(o + 4, false);
    const hi = isLE ? view.getUint32(o + 4, true) : view.getUint32(o, false);
    return hi * 0x100000000 + lo;
  };
  const rAddr = (o) => is64 ? r64(o) : r32(o);
  const addrSize = is64 ? 8 : 4;

  // ELF header
  const shoff = is64 ? Number(r64(40)) : r32(32);
  const shentsize = r16(is64 ? 58 : 46);
  const shnum = r16(is64 ? 60 : 48);
  const shstrndx = r16(is64 ? 62 : 50);

  // Section headers
  const sections = [];
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize;
    if (is64) {
      sections.push({
        nameIdx: r32(base),
        type: r32(base + 4),
        offset: Number(r64(base + 24)),
        size: Number(r64(base + 32)),
        link: r32(base + 40),
        entsize: Number(r64(base + 56)),
      });
    } else {
      sections.push({
        nameIdx: r32(base),
        type: r32(base),
        offset: r32(base + 16),
        size: r32(base + 20),
        link: r32(base + 24),
        entsize: r32(base + 36),
      });
    }
  }

  // Fix: re-parse properly for 32-bit
  const sections2 = [];
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize;
    if (is64) {
      sections2.push({
        nameIdx: r32(base),
        type: r32(base + 4),
        offset: Number(r64(base + 24)),
        size: Number(r64(base + 32)),
        link: r32(base + 40),
        entsize: Number(r64(base + 56)),
      });
    } else {
      sections2.push({
        nameIdx: r32(base + 0),
        type: r32(base + 4),
        offset: r32(base + 16),
        size: r32(base + 20),
        link: r32(base + 24),
        entsize: r32(base + 36),
      });
    }
  }

  // String table for section names
  const shstrSection = sections2[shstrndx];
  const readStr = (tableOff, idx) => {
    let end = idx;
    while (end < bytes.length && bytes[tableOff + end] !== 0) end++;
    return new TextDecoder().decode(bytes.slice(tableOff + idx, tableOff + end));
  };

  // Find .dynsym and .dynstr
  let dynSymSec = null, dynStrSec = null, symTabSec = null, strTabSec = null;
  for (const sec of sections2) {
    const name = readStr(shstrSection.offset, sec.nameIdx);
    if (name === ".dynsym") dynSymSec = sec;
    if (name === ".dynstr") dynStrSec = sec;
    if (name === ".symtab") symTabSec = sec;
    if (name === ".strtab") strTabSec = sec;
  }

  const symbols = [];
  const seen = new Set();

  const parseSymSection = (symSec, strSec) => {
    if (!symSec || !strSec || symSec.entsize === 0) return;
    const count = Math.floor(symSec.size / symSec.entsize);
    for (let i = 1; i < count; i++) {
      const base = symSec.offset + i * symSec.entsize;
      let nameIdx, value, size, info, shndx;
      if (is64) {
        nameIdx = r32(base);
        info = bytes[base + 4];
        shndx = r16(base + 6);
        value = r64(base + 8);
        size = r64(base + 16);
      } else {
        nameIdx = r32(base);
        value = r32(base + 4);
        size = r32(base + 8);
        info = bytes[base + 12];
        shndx = r16(base + 14);
      }
      const name = readStr(strSec.offset, nameIdx);
      if (!name || seen.has(name)) continue;
      seen.add(name);
      const type = info & 0xf;
      const bind = info >> 4;
      const typeStr = ["NOTYPE","OBJECT","FUNC","SECTION","FILE","COMMON","TLS"][type] || `UNK(${type})`;
      const bindStr = ["LOCAL","GLOBAL","WEAK"][bind] || `UNK(${bind})`;
      symbols.push({
        name,
        value: "0x" + (typeof value === "bigint" ? value : BigInt(value)).toString(16).padStart(is64 ? 16 : 8, "0"),
        size: Number(size),
        type: typeStr,
        bind: bindStr,
        defined: shndx !== 0,
      });
    }
  };

  parseSymSection(dynSymSec, dynStrSec);
  parseSymSection(symTabSec, strTabSec);

  return symbols;
}

// ─── Frida Script Generator ───────────────────────────────────────────────────
function generateFridaScript(symbolMap) {
  const lines = symbolMap.trim().split("\n");
  const entries = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("Il2Cpp.$config")) continue;

    // Format: il2cpp_name: () => Il2Cpp.module.findExportByName("SYMBOL")
    const match = trimmed.match(/(\w+):\s*\(\)\s*=>\s*Il2Cpp\.module\.findExportByName\("([^"]+)"\)/);
    if (match) {
      entries.push({ il2cppName: match[1], symbol: match[2] });
      continue;
    }

    // Fallback: address name or name address
    const parts = trimmed.split(/[\s=,\t]+/);
    if (parts.length >= 2) {
      const [a, b] = parts;
      const isHex = (s) => /^0x[0-9a-fA-F]+$/.test(s) || /^[0-9a-fA-F]{8,}$/.test(s);
      if (isHex(a)) entries.push({ il2cppName: b, symbol: a });
      else if (isHex(b)) entries.push({ il2cppName: a, symbol: b });
    }
  }

  if (entries.length === 0) throw new Error("No valid symbol entries found in map");

  const hooks = entries.map(({ il2cppName, symbol }) => `
  // ${il2cppName} -> ${symbol}
  try {
    const fn_${il2cppName} = Il2Cpp.module.findExportByName("${symbol}");
    if (fn_${il2cppName}) {
      Interceptor.attach(fn_${il2cppName}, {
        onEnter(args) { console.log("[+] ${il2cppName} called"); },
        onLeave(retval) { console.log("[+] ${il2cppName} returned:", retval); }
      });
    }
  } catch(e) { console.error("[-] Failed to hook ${il2cppName}:", e.message); }`).join("\n");

  return `// Frida Bridge — generated by IL2CPP Symbol Tools
// Symbols: ${entries.length} hooks
// Generated: ${new Date().toISOString()}

"use strict";

Java.perform(function() {
  console.log("[*] IL2CPP Frida Bridge starting...");

  const base = Module.findBaseAddress("libil2cpp.so");
  if (!base) { console.error("[-] libil2cpp.so not found!"); return; }
  console.log("[*] libil2cpp.so base:", base);

${hooks}

  console.log("[*] Bridge initialized — ${entries.length} hooks active");
});`;
}

// ─── UI Components ────────────────────────────────────────────────────────────
const palette = {
  bg: "#0d0f12",
  surface: "#131519",
  card: "#191c21",
  border: "#2a2d35",
  accent: "#4f8ef7",
  accentDim: "#1a2d4a",
  green: "#3ecf8e",
  greenDim: "#0f2e20",
  text: "#e8eaed",
  muted: "#8a8f9a",
  danger: "#f87171",
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${palette.bg}; color: ${palette.text}; font-family: 'Inter', sans-serif; }
  .mono { font-family: 'JetBrains Mono', monospace; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 20px; border-radius: 8px; border: 1px solid ${palette.border};
    background: ${palette.card}; color: ${palette.text}; font-size: 14px; font-weight: 500;
    cursor: pointer; transition: all 0.15s; font-family: 'Inter', sans-serif;
  }
  .btn:hover { background: #22262e; border-color: #3a3f4a; }
  .btn-accent { background: ${palette.accent}; border-color: ${palette.accent}; color: #fff; }
  .btn-accent:hover { background: #3a7ce6; border-color: #3a7ce6; }
  .btn-green { background: ${palette.green}; border-color: ${palette.green}; color: #0a1f15; }
  .btn-green:hover { background: #33b87a; border-color: #33b87a; }
  .drop-zone {
    border: 2px dashed ${palette.border}; border-radius: 12px;
    padding: 48px 32px; text-align: center; cursor: pointer;
    transition: all 0.2s; background: ${palette.surface};
  }
  .drop-zone:hover, .drop-zone.drag-over { border-color: ${palette.accent}; background: ${palette.accentDim}; }
  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 500; font-family: 'JetBrains Mono', monospace;
  }
  .tag-func { background: ${palette.accentDim}; color: ${palette.accent}; }
  .tag-obj { background: #1a2e1a; color: ${palette.green}; }
  .tag-notype { background: #2a2a1a; color: #c4a830; }
  .tag-other { background: #2a1a2a; color: #b07ad4; }
  .sym-row {
    display: grid; grid-template-columns: 1fr 160px 80px 70px 60px;
    gap: 8px; padding: 8px 12px; border-bottom: 1px solid #1e2128;
    font-size: 13px; align-items: center;
  }
  .sym-row:hover { background: #191c21; }
  .sym-header { background: ${palette.surface}; font-weight: 500; color: ${palette.muted}; font-size: 12px; border-radius: 8px 8px 0 0; }
  input[type=text] {
    background: ${palette.surface}; border: 1px solid ${palette.border}; border-radius: 8px;
    color: ${palette.text}; padding: 8px 12px; font-size: 14px; font-family: 'Inter', sans-serif;
    outline: none; width: 100%;
  }
  input[type=text]:focus { border-color: ${palette.accent}; }
  .frida-output {
    background: #0a0c0f; border: 1px solid ${palette.border}; border-radius: 8px;
    padding: 20px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
    line-height: 1.7; color: ${palette.green}; max-height: 480px; overflow-y: auto;
    white-space: pre; overflow-x: auto;
  }
  .nav-back {
    display: inline-flex; align-items: center; gap: 6px;
    color: ${palette.muted}; font-size: 14px; cursor: pointer; margin-bottom: 32px;
    background: none; border: none; font-family: 'Inter', sans-serif;
  }
  .nav-back:hover { color: ${palette.text}; }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: ${palette.bg}; }
  ::-webkit-scrollbar-thumb { background: ${palette.border}; border-radius: 3px; }
  .dumper-tabs { display: flex; gap: 4px; border-bottom: 1px solid ${palette.border}; margin-bottom: 12px; overflow-x: auto; }
  .dumper-tab {
    padding: 8px 14px; font-size: 13px; font-weight: 500; cursor: pointer;
    color: ${palette.muted}; border: none; background: none; font-family: 'Inter', sans-serif;
    border-bottom: 2px solid transparent; white-space: nowrap;
  }
  .dumper-tab:hover { color: ${palette.text}; }
  .dumper-tab.active { color: ${palette.accent}; border-bottom-color: ${palette.accent}; }
  .dump-view {
    background: #0a0c0f; border: 1px solid ${palette.border}; border-radius: 8px;
    padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
    line-height: 1.6; color: ${palette.text}; max-height: 560px; overflow: auto;
    white-space: pre; word-break: break-all;
  }
  .stat-box {
    background: ${palette.surface}; border: 1px solid ${palette.border}; border-radius: 10px;
    padding: 14px 16px;
  }
  .stat-label { font-size: 11px; color: ${palette.muted}; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
  .stat-value { font-size: 18px; font-weight: 600; color: ${palette.text}; font-family: 'JetBrains Mono', monospace; }
  .file-chip {
    display: inline-flex; align-items: center; gap: 8px;
    background: ${palette.surface}; border: 1px solid ${palette.border}; border-radius: 8px;
    padding: 8px 14px; font-size: 13px; color: ${palette.text}; cursor: pointer;
  }
  .file-chip:hover { border-color: ${palette.accent}; }
  .warning-box {
    background: #241a08; border: 1px solid #4a3a10; border-radius: 8px; padding: 12px 16px;
    font-size: 13px; color: #e0c068; font-family: 'JetBrains Mono', monospace; line-height: 1.6;
  }
`;

// ─── Pages ────────────────────────────────────────────────────────────────────

function HomePage({ onNav }) {
  return (
    <div style={{ minHeight: "100vh", background: palette.bg, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "40px 24px" }}>
      <div style={{ textAlign: "center", marginBottom: 48 }}>
        <p style={{ fontFamily: "'JetBrains Mono'", fontSize: 12, color: palette.accent, letterSpacing: "0.15em", marginBottom: 16, textTransform: "uppercase" }}>
          IL2CPP
        </p>
        <h1 style={{ fontSize: 42, fontWeight: 600, color: palette.text, marginBottom: 12, lineHeight: 1.2 }}>
          symbol and frida stuff
        </h1>
        <p style={{ color: palette.muted, fontSize: 16, maxWidth: 420, margin: "0 auto" }}>
          get symbols and patch frida bridges with them
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, width: "100%", maxWidth: 600, marginBottom: 48 }}>
        <button
          onClick={() => onNav("symbols")}
          style={{ background: palette.card, border: `1px solid ${palette.border}`, borderRadius: 12, padding: "28px 24px", cursor: "pointer", textAlign: "left", transition: "all 0.2s" }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = palette.accent; e.currentTarget.style.background = "#1a1e26"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = palette.border; e.currentTarget.style.background = palette.card; }}
        >
          <div style={{ width: 36, height: 36, borderRadius: 8, background: palette.accentDim, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={palette.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
            </svg>
          </div>
          <p style={{ fontWeight: 600, fontSize: 15, color: palette.text, marginBottom: 6 }}>symbol getter</p>
          <p style={{ fontSize: 13, color: palette.muted, lineHeight: 1.5 }}>get the symbols from libil2cpp.so</p>
        </button>

        <button
          onClick={() => onNav("metadata")}
          style={{ background: palette.card, border: `1px solid ${palette.border}`, borderRadius: 12, padding: "28px 24px", cursor: "pointer", textAlign: "left", transition: "all 0.2s" }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = palette.green; e.currentTarget.style.background = "#151e17"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = palette.border; e.currentTarget.style.background = palette.card; }}
        >
          <div style={{ width: 36, height: 36, borderRadius: 8, background: palette.greenDim, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={palette.green} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
            </svg>
          </div>
          <p style={{ fontWeight: 600, fontSize: 15, color: palette.text, marginBottom: 6 }}>metadata dumper</p>
          <p style={{ fontSize: 13, color: palette.muted, lineHeight: 1.5 }}>dump global-metadata.dat — types, methods, strings, addresses</p>
        </button>

        <button
          onClick={() => onNav("frida")}
          style={{ background: palette.card, border: `1px solid ${palette.border}`, borderRadius: 12, padding: "28px 24px", cursor: "pointer", textAlign: "left", transition: "all 0.2s" }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = palette.green; e.currentTarget.style.background = "#151e17"; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = palette.border; e.currentTarget.style.background = palette.card; }}
        >
          <div style={{ width: 36, height: 36, borderRadius: 8, background: palette.greenDim, display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={palette.green} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <p style={{ fontWeight: 600, fontSize: 15, color: palette.text, marginBottom: 6 }}>frida patcher</p>
          <p style={{ fontSize: 13, color: palette.muted, lineHeight: 1.5 }}>patches the frida bridge with your symbol map to make custom bridges</p>
        </button>
      </div>

      <a href="https://github.com" style={{ display: "inline-flex", alignItems: "center", gap: 8, color: palette.muted, fontSize: 13, textDecoration: "none" }}
        onMouseEnter={e => e.currentTarget.style.color = palette.text}
        onMouseLeave={e => e.currentTarget.style.color = palette.muted}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        view on github
      </a>
    </div>
  );
}

function SymbolGetter({ onBack }) {
  const [status, setStatus] = useState("idle"); // idle | loading | done | error
  const [error, setError] = useState("");
  const [symbols, setSymbols] = useState([]);
  const [filter, setFilter] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef();

  const processFile = async (file) => {
    if (!file) return;
    setStatus("loading");
    setError("");
    try {
      const buf = await file.arrayBuffer();
      const syms = parseELFSymbols(buf);
      setSymbols(syms);
      setStatus("done");
    } catch (e) {
      setError(e.message);
      setStatus("error");
    }
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) processFile(file);
  }, []);

  const downloadCSV = () => {
    const rows = [["name", "value", "size", "type", "bind", "defined"]];
    symbols.forEach(s => rows.push([s.name, s.value, s.size, s.type, s.bind, s.defined]));
    const csv = rows.map(r => r.join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "symbols.csv";
    a.click();
  };

  const filtered = filter
    ? symbols.filter(s => s.name.toLowerCase().includes(filter.toLowerCase()))
    : symbols;

  const tagClass = (type) => {
    if (type === "FUNC") return "tag-func";
    if (type === "OBJECT") return "tag-obj";
    if (type === "NOTYPE") return "tag-notype";
    return "tag-other";
  };

  return (
    <div style={{ minHeight: "100vh", background: palette.bg, padding: "40px 24px", maxWidth: 960, margin: "0 auto" }}>
      <button className="nav-back" onClick={onBack}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"/></svg>
        back
      </button>

      <div style={{ marginBottom: 32 }}>
        <p style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: palette.accent, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>symbol getter</p>
        <h1 style={{ fontSize: 28, fontWeight: 600, color: palette.text, marginBottom: 8 }}>upload the libil2cpp.so to get symbols</h1>
        <p style={{ color: palette.muted, fontSize: 14 }}>parses ELF symbol tables (.dynsym + .symtab) from the library</p>
      </div>

      {status !== "done" && (
        <div
          className={`drop-zone${dragging ? " drag-over" : ""}`}
          onClick={() => fileRef.current.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{ marginBottom: 24 }}
        >
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={dragging ? palette.accent : palette.muted} strokeWidth="1.5" style={{ marginBottom: 12 }}>
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          <p style={{ color: palette.text, fontWeight: 500, marginBottom: 4 }}>
            {status === "loading" ? "parsing symbols..." : "drop libil2cpp.so here"}
          </p>
          <p style={{ color: palette.muted, fontSize: 13 }}>or click to browse — only for the libil2cpp.so</p>
          <input ref={fileRef} type="file" style={{ display: "none" }} onChange={e => processFile(e.target.files[0])} />
        </div>
      )}

      {status === "error" && (
        <div style={{ background: "#1f0f0f", border: `1px solid #4a1515`, borderRadius: 8, padding: "12px 16px", marginBottom: 24 }}>
          <p style={{ color: palette.danger, fontSize: 14, fontFamily: "'JetBrains Mono'" }}>error: {error}</p>
        </div>
      )}

      {status === "done" && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <input type="text" placeholder="filter symbols..." value={filter} onChange={e => setFilter(e.target.value)} />
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ color: palette.muted, fontSize: 13 }}>{filtered.length.toLocaleString()} / {symbols.length.toLocaleString()} symbols</span>
              <button className="btn" onClick={downloadCSV}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                export csv
              </button>
              <button className="btn" onClick={() => { setStatus("idle"); setSymbols([]); setFilter(""); }}>reset</button>
            </div>
          </div>

          <div style={{ background: palette.surface, border: `1px solid ${palette.border}`, borderRadius: 12, overflow: "hidden" }}>
            <div className="sym-row sym-header">
              <span>name</span>
              <span className="mono">address</span>
              <span>size</span>
              <span>type</span>
              <span>bind</span>
            </div>
            <div style={{ maxHeight: 520, overflowY: "auto" }}>
              {filtered.slice(0, 500).map((s, i) => (
                <div key={i} className="sym-row mono" style={{ opacity: s.defined ? 1 : 0.5 }}>
                  <span style={{ fontSize: 12, wordBreak: "break-all", color: palette.text }}>{s.name}</span>
                  <span style={{ fontSize: 12, color: palette.accent }}>{s.value}</span>
                  <span style={{ fontSize: 12, color: palette.muted }}>{s.size > 0 ? s.size : "—"}</span>
                  <span><span className={`tag ${tagClass(s.type)}`}>{s.type}</span></span>
                  <span style={{ fontSize: 12, color: palette.muted }}>{s.bind}</span>
                </div>
              ))}
              {filtered.length > 500 && (
                <div style={{ padding: "12px", textAlign: "center", color: palette.muted, fontSize: 13 }}>
                  showing first 500 — use filter to narrow results or export csv for all
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function FridaPatcher({ onBack }) {
  const [status, setStatus] = useState("idle");
  const [error, setError] = useState("");
  const [script, setScript] = useState("");
  const [dragging, setDragging] = useState(false);
  const [fileName, setFileName] = useState("");
  const fileRef = useRef();

  const processFile = async (file) => {
    if (!file) return;
    setFileName(file.name);
    setStatus("loading");
    setError("");
    try {
      const text = await file.text();
      const result = generateFridaScript(text);
      setScript(result);
      setStatus("done");
    } catch (e) {
      setError(e.message);
      setStatus("error");
    }
  };

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) processFile(file);
  }, []);

  const downloadScript = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([script], { type: "text/javascript" }));
    a.download = "frida-bridge.js";
    a.click();
  };

  const copyScript = () => {
    navigator.clipboard.writeText(script).catch(() => {});
  };

  return (
    <div style={{ minHeight: "100vh", background: palette.bg, padding: "40px 24px", maxWidth: 960, margin: "0 auto" }}>
      <button className="nav-back" onClick={onBack}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"/></svg>
        back
      </button>

      <div style={{ marginBottom: 32 }}>
        <p style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: palette.green, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>frida bridge patcher</p>
        <h1 style={{ fontSize: 28, fontWeight: 600, color: palette.text, marginBottom: 8 }}>upload the symbolmap for your game</h1>
        <p style={{ color: palette.muted, fontSize: 14 }}>creates a frida bridge with the stuff — accepts address/name pairs in most formats</p>
      </div>

      <div style={{ background: palette.card, border: `1px solid ${palette.border}`, borderRadius: 10, padding: "12px 16px", marginBottom: 24, fontSize: 13, color: palette.muted, fontFamily: "'JetBrains Mono'" }}>
        <span style={{ color: palette.text }}>accepted formats: </span>
        0x12345678 MethodName &nbsp;|&nbsp; MethodName 0x12345678 &nbsp;|&nbsp; MethodName=0x12345678
      </div>

      {status !== "done" && (
        <div
          className={`drop-zone${dragging ? " drag-over" : ""}`}
          onClick={() => fileRef.current.click()}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          style={{ marginBottom: 24, borderColor: dragging ? palette.green : undefined }}
        >
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={dragging ? palette.green : palette.muted} strokeWidth="1.5" style={{ marginBottom: 12 }}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <p style={{ color: palette.text, fontWeight: 500, marginBottom: 4 }}>
            {status === "loading" ? "generating frida bridge..." : "drop your symbol map here"}
          </p>
          <p style={{ color: palette.muted, fontSize: 13 }}>txt, csv, or any plain text format</p>
          <input ref={fileRef} type="file" accept=".txt,.csv,.map,*" style={{ display: "none" }} onChange={e => processFile(e.target.files[0])} />
        </div>
      )}

      {status === "error" && (
        <div style={{ background: "#1f0f0f", border: `1px solid #4a1515`, borderRadius: 8, padding: "12px 16px", marginBottom: 24 }}>
          <p style={{ color: palette.danger, fontSize: 14, fontFamily: "'JetBrains Mono'" }}>error: {error}</p>
        </div>
      )}

      {status === "done" && (
        <>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ color: palette.green, fontSize: 13, fontFamily: "'JetBrains Mono'" }}>✓</span>
              <span style={{ color: palette.text, fontSize: 14, fontWeight: 500 }}>frida-bridge.js</span>
              <span style={{ color: palette.muted, fontSize: 13 }}>from {fileName}</span>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn" onClick={copyScript}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                copy
              </button>
              <button className="btn btn-green" onClick={downloadScript}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                download .js
              </button>
              <button className="btn" onClick={() => { setStatus("idle"); setScript(""); setFileName(""); }}>reset</button>
            </div>
          </div>
          <div className="frida-output">{script}</div>
        </>
      )}
    </div>
  );
}

function MetadataDumper({ onBack }) {
  const [status, setStatus] = useState("idle"); // idle | loading | done | error
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [tab, setTab] = useState("dump");
  const [metaName, setMetaName] = useState("");
  const [binName, setBinName] = useState("");
  const metaRef = useRef();
  const binRef = useRef();

  const metaBufRef = useRef(null);
  const binBufRef = useRef(null);

  const pickMeta = async (file) => {
    if (!file) return;
    setMetaName(file.name);
    metaBufRef.current = await file.arrayBuffer();
  };

  const pickBin = async (file) => {
    if (!file) return;
    setBinName(file.name);
    binBufRef.current = await file.arrayBuffer();
  };

  const run = () => {
    if (!metaBufRef.current) {
      setError("global-metadata.dat is required. The binary is optional but needed for type names and method addresses.");
      setStatus("error");
      return;
    }
    setStatus("loading");
    setError("");
    setTimeout(() => {
      try {
        const res = analyzeMetadata({
          metadata: metaBufRef.current,
          binary: binBufRef.current,
        });
        setResult(res);
        setTab("dump");
        setStatus("done");
      } catch (e) {
        setError(e && e.stack ? e.stack : String(e));
        setStatus("error");
      }
    }, 30);
  };

  const download = (filename, content, type) => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type: type || "text/plain" }));
    a.download = filename;
    a.click();
  };

  const currentTabContent = () => {
    if (!result || !result.ok) return "";
    switch (tab) {
      case "dump": return result.dumpCs;
      case "strings": return result.stringsDump;
      case "methods": return result.methodTableDump;
      case "json": return result.jsonDump;
      default: return "";
    }
  };

  const tabs = [
    { id: "dump", label: "dump.cs" },
    { id: "strings", label: "strings" },
    { id: "methods", label: "methods" },
    { id: "json", label: "json" },
  ];

  return (
    <div style={{ minHeight: "100vh", background: palette.bg, padding: "40px 24px", maxWidth: 1000, margin: "0 auto" }}>
      <button className="nav-back" onClick={onBack}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 18 9 12 15 6"/></svg>
        back
      </button>

      <div style={{ marginBottom: 32 }}>
        <p style={{ fontFamily: "'JetBrains Mono'", fontSize: 11, color: palette.green, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>global-metadata dumper</p>
        <h1 style={{ fontSize: 28, fontWeight: 600, color: palette.text, marginBottom: 8 }}>dump your global-metadata.dat</h1>
        <p style={{ color: palette.muted, fontSize: 14 }}>drop global-metadata.dat (required) + GameAssembly.dll / libil2cpp.so (optional, for type names &amp; method addresses)</p>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap", alignItems: "center" }}>
        <div className="file-chip" onClick={() => metaRef.current.click()} title="click to browse">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          <span>{metaName || "global-metadata.dat"}</span>
        </div>
        <div className="file-chip" onClick={() => binRef.current.click()} title="optional — click to browse">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M8 7V5a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
          <span>{binName || "binary (optional)"}</span>
        </div>
        <button className="btn btn-green" onClick={run} disabled={status === "loading"}>
          {status === "loading" ? "dumping..." : "dump it"}
        </button>
        <input ref={metaRef} type="file" style={{ display: "none" }} onChange={e => pickMeta(e.target.files[0])} />
        <input ref={binRef} type="file" accept=".dll,.so,.dylib,*" style={{ display: "none" }} onChange={e => pickBin(e.target.files[0])} />
      </div>

      {status === "error" && (
        <div style={{ background: "#1f0f0f", border: `1px solid #4a1515`, borderRadius: 8, padding: "12px 16px", marginBottom: 24, maxHeight: 240, overflow: "auto" }}>
          <p style={{ color: palette.danger, fontSize: 13, fontFamily: "'JetBrains Mono'", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{error}</p>
        </div>
      )}

      {status === "done" && result && result.ok && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginBottom: 16 }}>
            <div className="stat-box">
              <div className="stat-label">metadata version</div>
              <div className="stat-value">v{result.info.version}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">unity</div>
              <div className="stat-value" style={{ fontSize: 13 }}>{result.info.versionLabel}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">types</div>
              <div className="stat-value">{result.typeDefs.length.toLocaleString()}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">methods</div>
              <div className="stat-value">{result.methodDefs.length.toLocaleString()}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">addresses</div>
              <div className="stat-value">{result.methodAddresses.size.toLocaleString()}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">binary</div>
              <div className="stat-value" style={{ fontSize: 13 }}>
                {result.info.binaryType ? `${result.info.binaryType}${result.info.is64 ? "64" : "32"}` : "none"}
              </div>
            </div>
          </div>

          {result.warnings.length > 0 && (
            <div className="warning-box" style={{ marginBottom: 16 }}>
              {result.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
            </div>
          )}

          <div className="dumper-tabs">
            {tabs.map(t => (
              <button key={t.id} className={`dumper-tab${tab === t.id ? " active" : ""}`} onClick={() => setTab(t.id)}>{t.label}</button>
            ))}
          </div>

          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginBottom: 8 }}>
            <button className="btn" onClick={() => download(`dump.cs`, result.dumpCs)}>dump.cs</button>
            <button className="btn" onClick={() => download(`strings.txt`, result.stringsDump)}>strings.txt</button>
            <button className="btn" onClick={() => download(`methods.tsv`, result.methodTableDump)}>methods.tsv</button>
            <button className="btn" onClick={() => download(`dump.json`, result.jsonDump)}>dump.json</button>
          </div>

          <div className="dump-view">{currentTabContent()}</div>
        </>
      )}
    </div>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState("home");

  return (
    <>
      <style>{css}</style>
      {page === "home" && <HomePage onNav={setPage} />}
      {page === "symbols" && <SymbolGetter onBack={() => setPage("home")} />}
      {page === "metadata" && <MetadataDumper onBack={() => setPage("home")} />}
      {page === "frida" && <FridaPatcher onBack={() => setPage("home")} />}
    </>
  );
}