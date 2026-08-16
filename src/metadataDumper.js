const METADATA_MAGIC = 0xfab11baf;
const METADATA_MAGIC_STRIPPED = 0xfab11bae;

const UNITY_VERSION_LABELS = {
  16: '5.3.4 and earlier',
  17: '5.3.5',
  18: '5.4',
  19: '5.5 / 5.6',
  20: '2017.1',
  21: '2017.2 - 2017.4',
  22: '2018.1 - 2018.2',
  23: '2018.3',
  24.0: '2017.1 - 2018.4',
  24.1: '2018.4.x',
  24.2: '2019.1',
  24.3: '2019.2 / 2019.3',
  24.4: '2019.3.7+',
  24.5: '2019.4.15+',
  27: '2020.1',
  27.1: '2020.2',
  27.2: '2020.3 - 2021.1',
  29: '2021.2 - 2021.3',
  29.1: '2022.1 - 2022.2',
  29.2: '2022.3',
  31: '2022.3.36+ / Unity 6',
};

const PRIMITIVE_NAMES = [
  'END', 'VOID', 'BOOLEAN', 'CHAR', 'I1', 'U1', 'I2', 'U2', 'I4', 'U4', 'I8', 'U8', 'R4', 'R8',
  'STRING', 'PTR', 'BYREF', 'VALUETYPE', 'CLASS', 'VAR', 'ARRAY', 'GENERICINST', 'TYPEDBYREF',
  'I', 'U', 'FNPTR', 'OBJECT', 'SZARRAY', 'MVAR', 'CMOD_REQD', 'CMOD_OPT', 'INTERNAL',
];

const METHOD_ACCESS = ['private', 'private', 'private', 'internal', 'protected', 'protected internal', 'public'];
const TYPE_ACCESS = ['private', 'private', 'internal', 'private', 'protected', 'protected internal', 'public'];

function hex(v) {
  return '0x' + (v >>> 0).toString(16);
}

function readU32LE(dv, off) {
  if (off < 0 || off + 4 > dv.byteLength) return undefined;
  return dv.getUint32(off, true);
}

function readU64LE(dv, off) {
  if (off < 0 || off + 8 > dv.byteLength) return undefined;
  return dv.getUint32(off, true) + dv.getUint32(off + 4, true) * 0x100000000;
}

function readAscii(dv, off, maxLen) {
  if (off < 0 || off >= dv.byteLength) return '';
  const end = Math.min(dv.byteLength, off + (maxLen || 1024));
  let s = '';
  for (let i = off; i < end; i++) {
    const c = dv.getUint8(i);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function isVersionAtLeast(v, min) {
  return v + 0.001 >= min;
}

function isVersionAtMost(v, max) {
  return v - 0.001 <= max;
}

function versionLabel(v) {
  return UNITY_VERSION_LABELS[v] || UNITY_VERSION_LABELS[Math.floor(v)] || 'unknown';
}

class WarningCollector {
  constructor() {
    this.list = [];
    this._seen = new Set();
  }
  push(msg) {
    if (this._seen.has(msg)) return;
    this._seen.add(msg);
    this.list.push(msg);
  }
  get() {
    return this.list;
  }
}

/* ------------------------------------------------------------------ */
/* Gated field tables (mirrors Il2CppDumper / Il2CppInspector)         */
/* ------------------------------------------------------------------ */

function normalizeHeaderFields(rows) {
  return rows.map(([name, min, max]) => [name, 4, min, max]);
}

const HEADER_FIELDS = normalizeHeaderFields([
  ['stringLiteralOffset', null, null],
  ['stringLiteralSize', null, null],
  ['stringLiteralDataOffset', null, null],
  ['stringLiteralDataSize', null, null],
  ['stringOffset', null, null],
  ['stringSize', null, null],
  ['eventsOffset', null, null],
  ['eventsSize', null, null],
  ['propertiesOffset', null, null],
  ['propertiesSize', null, null],
  ['methodsOffset', null, null],
  ['methodsSize', null, null],
  ['parameterDefaultValuesOffset', null, null],
  ['parameterDefaultValuesSize', null, null],
  ['fieldDefaultValuesOffset', null, null],
  ['fieldDefaultValuesSize', null, null],
  ['fieldAndParameterDefaultValueDataOffset', null, null],
  ['fieldAndParameterDefaultValueDataSize', null, null],
  ['fieldMarshaledSizesOffset', null, null],
  ['fieldMarshaledSizesSize', null, null],
  ['parametersOffset', null, null],
  ['parametersSize', null, null],
  ['fieldsOffset', null, null],
  ['fieldsSize', null, null],
  ['genericParametersOffset', null, null],
  ['genericParametersSize', null, null],
  ['genericParameterConstraintsOffset', null, null],
  ['genericParameterConstraintsSize', null, null],
  ['genericContainersOffset', null, null],
  ['genericContainersSize', null, null],
  ['nestedTypesOffset', null, null],
  ['nestedTypesSize', null, null],
  ['interfacesOffset', null, null],
  ['interfacesSize', null, null],
  ['vtableMethodsOffset', null, null],
  ['vtableMethodsSize', null, null],
  ['interfaceOffsetsOffset', null, null],
  ['interfaceOffsetsSize', null, null],
  ['typeDefinitionsOffset', null, null],
  ['typeDefinitionsSize', null, null],
  ['rgctxEntriesOffset', null, 24.1],
  ['rgctxEntriesCount', null, 24.1],
  ['imagesOffset', null, null],
  ['imagesSize', null, null],
  ['assembliesOffset', null, null],
  ['assembliesSize', null, null],
  ['metadataUsageListsOffset', 19, 24.5],
  ['metadataUsageListsCount', 19, 24.5],
  ['metadataUsagePairsOffset', 19, 24.5],
  ['metadataUsagePairsCount', 19, 24.5],
  ['fieldRefsOffset', 19, null],
  ['fieldRefsSize', 19, null],
  ['referencedAssembliesOffset', 20, null],
  ['referencedAssembliesSize', 20, null],
  ['attributesInfoOffset', 21, 27.2],
  ['attributesInfoCount', 21, 27.2],
  ['attributeTypesOffset', 21, 27.2],
  ['attributeTypesCount', 21, 27.2],
  ['attributeDataOffset', 29, null],
  ['attributeDataSize', 29, null],
  ['attributeDataRangeOffset', 29, null],
  ['attributeDataRangeSize', 29, null],
  ['unresolvedVirtualCallParameterTypesOffset', 22, null],
  ['unresolvedVirtualCallParameterTypesSize', 22, null],
  ['unresolvedVirtualCallParameterRangesOffset', 22, null],
  ['unresolvedVirtualCallParameterRangesSize', 22, null],
  ['windowsRuntimeTypeNamesOffset', 23, null],
  ['windowsRuntimeTypeNamesSize', 23, null],
  ['windowsRuntimeStringsOffset', 27, null],
  ['windowsRuntimeStringsSize', 27, null],
  ['exportedTypeDefinitionsOffset', 24, null],
  ['exportedTypeDefinitionsSize', 24, null],
  ['methodSpecsOnGenericTypeOffset', 31, null],
  ['methodSpecsOnGenericTypeSize', 31, null],
  ['genericMethodSpecsOnTypeOffset', 31, null],
  ['genericMethodSpecsOnTypeSize', 31, null],
  ['methodSpecsOffset2', 31, null],
  ['methodSpecsSize2', 31, null],
  ['genericMethodFunctionsDefinitionsOffset', 31, null],
  ['genericMethodFunctionsDefinitionsSize', 31, null],
  ['genericMethodFunctionsDefinitionsWithAdjustorOffset', 31, null],
  ['genericMethodFunctionsDefinitionsWithAdjustorSize', 31, null],
  ['invokerIndicesOffset', 31, null],
  ['invokerIndicesSize', 31, null],
  ['rgctxRangesOffset', 31, null],
  ['rgctxRangesSize', 31, null],
  ['rgctxValuesOffset', 31, null],
  ['rgctxValuesSize', 31, null],
  ['staticConstructorTypeIndicesOffset', 31, null],
  ['staticConstructorTypeIndicesSize', 31, null],
]);

const TYPE_DEF_FIELDS = [
  ['nameIndex', 4], ['namespaceIndex', 4], ['customAttributeIndex', 4, null, 24.0],
  ['byvalTypeIndex', 4], ['byrefTypeIndex', 4, null, 24.5],
  ['declaringTypeIndex', 4], ['parentIndex', 4], ['elementTypeIndex', 4],
  ['rgctxStartIndex', 4, null, 24.1], ['rgctxCount', 4, null, 24.1],
  ['genericContainerIndex', 4],
  ['delegateWrapperFromManagedToNativeIndex', 4, null, 22], ['marshalingFunctionsIndex', 4, null, 22],
  ['ccwFunctionIndex', 4, 21, 22], ['guidIndex', 4, 21, 22],
  ['flags', 4],
  ['fieldStart', 4], ['methodStart', 4], ['eventStart', 4], ['propertyStart', 4],
  ['nestedTypesStart', 4], ['interfacesStart', 4], ['vtableMethodsStart', 4], ['interfaceOffsetsStart', 4],
  ['method_count', 2], ['property_count', 2], ['field_count', 2], ['event_count', 2],
  ['nested_type_count', 2], ['vtable_method_count', 2], ['interfaces_count', 2], ['interface_offsets_count', 2],
  ['bitfield', 4],
  ['token', 4, 19, null],
];

const METHOD_DEF_FIELDS = [
  ['nameIndex', 4], ['declaringType', 4], ['returnType', 4],
  ['returnParameterToken', 4, 31, null],
  ['parameterStart', 4],
  ['customAttributeIndex', 4, null, 24.0],
  ['genericContainerIndex', 4],
  ['methodIndex', 4, null, 24.1], ['invokerIndex', 4, null, 24.1], ['delegateWrapperIndex', 4, null, 24.1],
  ['rgctxStartIndex', 4, null, 24.1], ['rgctxCount', 4, null, 24.1],
  ['token', 4],
  ['flags', 2], ['iflags', 2], ['slot', 2], ['parameterCount', 2],
];

const PARAMETER_DEF_FIELDS = [
  ['nameIndex', 4], ['token', 4], ['customAttributeIndex', 4, null, 24.0], ['typeIndex', 4],
];

const FIELD_DEF_FIELDS = [
  ['nameIndex', 4], ['typeIndex', 4], ['customAttributeIndex', 4, null, 24.0], ['token', 4, 19, null],
];

const PROPERTY_DEF_FIELDS = [
  ['nameIndex', 4], ['get', 4], ['set', 4], ['attrs', 4], ['customAttributeIndex', 4, null, 24.0], ['token', 4, 19, null],
];

const EVENT_DEF_FIELDS = [
  ['nameIndex', 4], ['typeIndex', 4], ['add', 4], ['remove', 4], ['raise', 4],
  ['customAttributeIndex', 4, null, 24.0], ['token', 4, 19, null],
];

const IMAGE_DEF_FIELDS = [
  ['nameIndex', 4], ['assemblyIndex', 4], ['typeStart', 4], ['typeCount', 4],
  ['exportedTypeStart', 4, 24, null], ['exportedTypeCount', 4, 24, null],
  ['entryPointIndex', 4],
  ['token', 4, 19, null],
  ['customAttributeStart', 4, 24.1, null], ['customAttributeCount', 4, 24.1, null],
];

const ASSEMBLY_DEF_FIELDS = [
  ['imageIndex', 4],
  ['token', 4, 24.1, null],
  ['customAttributeIndex', 4, null, 24.0],
  ['referencedAssemblyStart', 4, 20, null],
  ['referencedAssemblyCount', 4, 20, null],
];

const ASSEMBLY_NAME_FIELDS = [
  ['nameIndex', 4], ['cultureIndex', 4], ['hashValueIndex', 4, null, 24.3], ['publicKeyIndex', 4],
  ['hash_alg', 4], ['hash_len', 4], ['flags', 4], ['major', 4], ['minor', 4], ['build', 4], ['revision', 4],
  ['public_key_token', 8],
];

function gatedSize(fields, version) {
  let s = 0;
  for (const f of fields) {
    const [, size, min, max] = f;
    if (min !== null && min !== undefined && !isVersionAtLeast(version, min)) continue;
    if (max !== null && max !== undefined && !isVersionAtMost(version, max)) continue;
    s += size;
  }
  return s;
}

function readGated(dv, base, fields, version, index) {
  const out = {};
  const total = gatedSize(fields, version);
  let off = 0;
  for (const [name, size, min, max] of fields) {
    if (min !== null && min !== undefined && !isVersionAtLeast(version, min)) continue;
    if (max !== null && max !== undefined && !isVersionAtMost(version, max)) continue;
    const abs = base + index * total + off;
    if (abs + size <= dv.byteLength) {
      if (size === 4) out[name] = dv.getInt32(abs, true);
      else if (size === 2) out[name] = dv.getUint16(abs, true);
      else if (size === 8) out[name] = readU64LE(dv, abs);
    } else {
      out[name] = undefined;
    }
    off += size;
  }
  return out;
}

function readGatedField(dv, base, fields, version, index, name) {
  const total = gatedSize(fields, version);
  let off = 0;
  for (const [fName, size, min, max] of fields) {
    if (min !== null && min !== undefined && !isVersionAtLeast(version, min)) continue;
    if (max !== null && max !== undefined && !isVersionAtMost(version, max)) continue;
    if (fName === name) {
      const abs = base + index * total + off;
      if (size === 4) return readU32LE(dv, abs);
      if (size === 2) {
        const v = readU32LE(dv, abs);
        return v === undefined ? undefined : dv.getUint16(abs, true);
      }
      if (size === 8) return readU64LE(dv, abs);
      return undefined;
    }
    off += size;
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* Binary container (PE / ELF)                                         */
/* ------------------------------------------------------------------ */

class BinaryFile {
  constructor(buffer, warnings) {
    this.buffer = buffer;
    this.dv = new DataView(buffer);
    this.warnings = warnings;
    this.isPE = false;
    this.isELF = false;
    this.is64 = false;
    this.pointerSize = 4;
    this.imageBase = 0;
    this.virtualToFile = [];
    this.fileToVirtual = [];
    this.sections = [];
    this.execRanges = [];
    if (this.dv.byteLength >= 0x40 && readU32LE(this.dv, 0) === 0x00004550) this._parsePE();
    else if (this.dv.byteLength >= 0x40 && readU32LE(this.dv, 0) === 0x464c457f) this._parseELF();
    else warnings.push('Binary does not look like a PE or ELF file; addresses will not be resolved.');
  }

  _addMapped(fileOff, fileSize, va, virtualSize, flags) {
    if (fileOff < 0 || fileSize <= 0) return;
    this.sections.push({ fileOff, fileSize, va, virtualSize, flags });
    if (fileOff + fileSize <= this.dv.byteLength) {
      this.virtualToFile.push([va, va + virtualSize, fileOff]);
      this.fileToVirtual.push([fileOff, fileOff + fileSize, va]);
      if (flags && flags.exec) this.execRanges.push([va, va + Math.max(fileSize, virtualSize)]);
    }
  }

  _parsePE() {
    this.isPE = true;
    const peOff = readU32LE(this.dv, 0x3c);
    if (peOff === undefined || peOff + 0x18 > this.dv.byteLength) return;
    const coffOff = peOff + 4;
    const numSections = readU32LE(this.dv, coffOff + 2);
    const optSize = readU32LE(this.dv, coffOff + 16);
    const optMagic = readU32LE(this.dv, coffOff + 20);
    this.is64 = optMagic === 0x20b;
    this.pointerSize = this.is64 ? 8 : 4;
    this.imageBase = readU64LE(this.dv, coffOff + 24 + (this.is64 ? 24 : 28));
    if (this.imageBase === undefined) this.imageBase = 0;
    const secOff = coffOff + 20 + optSize;
    for (let i = 0; i < numSections; i++) {
      const s = secOff + i * 40;
      const virtualSize = readU32LE(this.dv, s + 8);
      const virtualAddress = readU32LE(this.dv, s + 12);
      const sizeOfRawData = readU32LE(this.dv, s + 16);
      const pointerToRawData = readU32LE(this.dv, s + 20);
      const characteristics = readU32LE(this.dv, s + 36);
      const isExec = (characteristics & 0x20000000) !== 0;
      this._addMapped(pointerToRawData, sizeOfRawData, this.imageBase + virtualAddress, virtualSize, { exec: isExec });
    }
    this._finishMaps();
  }

  _parseELF() {
    this.isELF = true;
    const eiClass = this.dv.getUint8(4);
    this.is64 = eiClass === 2;
    this.pointerSize = this.is64 ? 8 : 4;
    if (this.is64) {
      const e_phoff = readU64LE(this.dv, 0x20);
      const e_phentsize = readU32LE(this.dv, 0x36) || 56;
      const e_phnum = readU32LE(this.dv, 0x38);
      for (let i = 0; i < e_phnum; i++) {
        const p = e_phoff + i * e_phentsize;
        if (readU32LE(this.dv, p) === 1) {
          const p_offset = readU64LE(this.dv, p + 8);
          const p_vaddr = readU64LE(this.dv, p + 16);
          const p_filesz = readU64LE(this.dv, p + 32);
          const p_memsz = readU64LE(this.dv, p + 40);
          const p_flags = readU32LE(this.dv, p + 4);
          this._addMapped(p_offset, p_filesz, p_vaddr, p_memsz, { exec: (p_flags & 1) !== 0 });
        }
      }
    } else {
      const phOff32 = readU32LE(this.dv, 0x1c);
      const phEnt = readU32LE(this.dv, 0x2a) || 32;
      const phNum = readU32LE(this.dv, 0x2c);
      for (let i = 0; i < phNum; i++) {
        const p = phOff32 + i * phEnt;
        if (readU32LE(this.dv, p) === 1) {
          const p_offset = readU32LE(this.dv, p + 4);
          const p_vaddr = readU32LE(this.dv, p + 8);
          const p_filesz = readU32LE(this.dv, p + 16);
          const p_memsz = readU32LE(this.dv, p + 20);
          const p_flags = readU32LE(this.dv, p + 24);
          this._addMapped(p_offset, p_filesz, p_vaddr, p_memsz, { exec: (p_flags & 1) !== 0 });
        }
      }
    }
    this._finishMaps();
  }

  _finishMaps() {
    this.virtualToFile.sort((a, b) => a[0] - b[0]);
    this.fileToVirtual.sort((a, b) => a[0] - b[0]);
  }

  isMappedFileOffset(off) {
    for (const [lo, hi] of this.fileToVirtual) {
      if (off >= lo && off < hi) return true;
    }
    return false;
  }

  vaToFileOffset(va) {
    for (const [vlo, vhi, foff] of this.virtualToFile) {
      if (va >= vlo && va < vhi) return foff + (va - vlo);
    }
    return -1;
  }

  fileOffsetToVa(off) {
    for (const [flo, fhi, va] of this.fileToVirtual) {
      if (off >= flo && off < fhi) return va + (off - flo);
    }
    return -1;
  }

  vaToRva(va) {
    if (!this.isPE) return -1;
    return va - this.imageBase;
  }

  readPtrAtVa(va) {
    const off = this.vaToFileOffset(va);
    if (off < 0) return -1;
    return this.pointerSize === 8 ? readU64LE(this.dv, off) : readU32LE(this.dv, off);
  }
}

/* ------------------------------------------------------------------ */
/* Metadata header detection (obfuscation-resilient)                   */
/* ------------------------------------------------------------------ */

function probeHeader(dv, magicOff) {
  const sanity = readU32LE(dv, magicOff);
  if (sanity !== METADATA_MAGIC && sanity !== METADATA_MAGIC_STRIPPED) return null;
  const version = readU32LE(dv, magicOff + 4);
  if (version === undefined || version < 16 || version > 50) return null;
  return { headerOff: magicOff, version, magic: sanity, stripped: sanity === METADATA_MAGIC_STRIPPED };
}

function detectVersion(dv, probe, warnings) {
  const version = probe.version;
  if (version !== 24) return version;
  const slOffset = readU32LE(dv, probe.headerOff + 8);
  if (slOffset === 264) {
    warnings.push('Metadata version 24.2 detected via header length probe.');
    return 24.2;
  }
  return 24.0;
}

function locateHeader(dv, warnings) {
  const probes = [];
  const u8 = new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
  const magicBytes = [0xaf, 0x1b, 0xb1, 0xfa];
  const strippedBytes = [0xae, 0x1b, 0xb1, 0xfa];
  for (let i = 0; i + 4 <= u8.length; i++) {
    if (u8[i] === magicBytes[0] && u8[i + 1] === magicBytes[1] && u8[i + 2] === magicBytes[2] && u8[i + 3] === magicBytes[3]
      || u8[i] === strippedBytes[0] && u8[i + 1] === strippedBytes[1] && u8[i + 2] === strippedBytes[2] && u8[i + 3] === strippedBytes[3]) {
      const probe = probeHeader(dv, i);
      if (probe) probes.push(probe);
      i += 3;
    }
  }
  if (probes.length === 0) {
    warnings.push('No global-metadata magic found anywhere in the file.');
    return null;
  }
  let best = null;
  let bestScore = -1;
  for (const p of probes) {
    let score = 0;
    if (!p.stripped) score += 100;
    const headerSize = gatedSize(HEADER_FIELDS, p.version) + 8;
    const slOffset = readU32LE(dv, p.headerOff + 8);
    if (slOffset === headerSize) score += 50;
    else if (slOffset !== undefined && slOffset >= headerSize && slOffset < dv.byteLength) score += 20;
    const sOffset = readU32LE(dv, p.headerOff + 20);
    if (sOffset !== undefined && sOffset >= headerSize && sOffset < dv.byteLength) score += 10;
    const tdOffset = readU32LE(dv, p.headerOff + 8 + 38 * 4);
    if (tdOffset !== undefined && tdOffset > slOffset && tdOffset < dv.byteLength) score += 10;
    if (score > bestScore) {
      bestScore = score;
      best = p;
    }
  }
  return best;
}

/* ------------------------------------------------------------------ */
/* Main analysis                                                       */
/* ------------------------------------------------------------------ */

export function analyzeMetadata({ metadata, binary }) {
  const warnings = new WarningCollector();
  const mdv = new DataView(metadata);

  const probe = locateHeader(mdv, warnings);
  if (!probe) {
    return {
      ok: false,
      error: 'Could not locate the global-metadata header. The file may be corrupt, encrypted, or not a Unity global-metadata.dat.',
      warnings: warnings.get(),
    };
  }

  let vf = detectVersion(mdv, probe, warnings);
  const headerOff = probe.headerOff;
  const headerSize = gatedSize(HEADER_FIELDS, vf) + 8;

  const info = {
    magic: probe.magic,
    magicHex: hex(probe.magic),
    stripped: probe.stripped,
    versionInt: probe.version,
    version: vf,
    versionLabel: versionLabel(vf),
    headerOffset: headerOff,
    headerSize,
    fileSize: metadata.byteLength,
    preHeaderBytes: headerOff,
  };

  const readHeaderField = (name) => readGatedField(mdv, headerOff + 8, HEADER_FIELDS, vf, 0, name);

  const sections = {};
  for (const f of HEADER_FIELDS) {
    sections[f[0]] = readHeaderField(f[0]);
  }

  function sectionBounds(name, offField, sizeField) {
    const off = sections[offField];
    const size = sections[sizeField];
    if (off === undefined || size === undefined || off < 0 || size < 0) return { valid: false };
    const end = off + size;
    if (off < headerOff || end > metadata.byteLength) {
      warnings.push(`Section ${name} is out of bounds (offset ${off}, size ${size}).`);
      return { valid: false };
    }
    return { valid: true, off, size, end };
  }

  function parseArray(offField, sizeField, itemSize, name, builder) {
    const b = sectionBounds(name, offField, sizeField);
    if (!b.valid || itemSize <= 0) return [];
    const count = Math.floor(b.size / itemSize);
    const out = new Array(count);
    for (let i = 0; i < count; i++) out[i] = builder(mdv, b.off, i);
    return out;
  }

  /* --- string literals --- */
  const stringLiterals = parseArray('stringLiteralOffset', 'stringLiteralSize', 8, 'stringLiterals', (dv, base, i) => {
    const length = readU32LE(dv, base + i * 8);
    const dataIndex = readU32LE(dv, base + i * 8 + 4);
    let value = null;
    const dataBase = sections.stringLiteralDataOffset;
    const dataSize = sections.stringLiteralDataSize;
    if (dataIndex !== undefined && length !== undefined && dataBase !== undefined && dataSize !== undefined
      && length >= 0 && length < (1 << 20) && dataIndex + length <= dataSize) {
      let s = '';
      for (let k = 0; k < length; k++) {
        const c = dv.getUint8(dataBase + dataIndex + k);
        s += c === 0 ? '\u2400' : String.fromCharCode(c);
      }
      value = s;
    }
    return { length, dataIndex, value };
  });

  /* --- string table --- */
  function readString(index) {
    const base = sections.stringOffset;
    const size = sections.stringSize;
    if (index === undefined || base === undefined || size === undefined) return '';
    if (index < 0 || index >= size) return '';
    return readAscii(mdv, base + index, 512);
  }

  /* --- images (read before assemblies for v24 probes) --- */
  const imageSize = gatedSize(IMAGE_DEF_FIELDS, vf);
  let images = parseArray('imagesOffset', 'imagesSize', imageSize, 'images', (dv, base, i) => {
    const img = readGated(dv, base, IMAGE_DEF_FIELDS, vf, i);
    return { ...img, name: readString(img.nameIndex) };
  });

  if (vf === 24.0) {
    const hasNonUnitToken = images.some((x) => x.token !== undefined && x.token !== 1);
    if (hasNonUnitToken) {
      warnings.push('Metadata version 24.1 detected via image token probe.');
      vf = 24.1;
      images = parseArray('imagesOffset', 'imagesSize', gatedSize(IMAGE_DEF_FIELDS, vf), 'images', (dv, base, i) => {
        const img = readGated(dv, base, IMAGE_DEF_FIELDS, vf, i);
        return { ...img, name: readString(img.nameIndex) };
      });
    }
  }
  info.version = vf;

  /* --- assemblies (size probe for v24.4) --- */
  let assemblySize = gatedSize(ASSEMBLY_DEF_FIELDS, vf) + gatedSize(ASSEMBLY_NAME_FIELDS, vf);
  if ((vf === 24.2 || vf === 24.3) && sections.assembliesSize !== undefined) {
    const n68 = Math.floor(sections.assembliesSize / 68);
    if (n68 < images.length) {
      warnings.push('Metadata version 24.4 detected via assembly size probe.');
      vf = 24.4;
      assemblySize = gatedSize(ASSEMBLY_DEF_FIELDS, vf) + gatedSize(ASSEMBLY_NAME_FIELDS, vf);
    }
  }
  info.version = vf;

  const assemblies = parseArray('assembliesOffset', 'assembliesSize', assemblySize, 'assemblies', (dv, base, i) => {
    const a = readGated(dv, base, ASSEMBLY_DEF_FIELDS, vf, i);
    const n = readGated(dv, base + gatedSize(ASSEMBLY_DEF_FIELDS, vf), ASSEMBLY_NAME_FIELDS, vf, i);
    return {
      imageIndex: a.imageIndex,
      token: a.token,
      referencedAssemblyStart: a.referencedAssemblyStart,
      referencedAssemblyCount: a.referencedAssemblyCount,
      nameIndex: n.nameIndex,
      cultureIndex: n.cultureIndex,
      publicKeyIndex: n.publicKeyIndex,
      hash_alg: n.hash_alg,
      hash_len: n.hash_len,
      flags: n.flags,
      major: n.major,
      minor: n.minor,
      build: n.build,
      revision: n.revision,
      public_key_token: n.public_key_token,
      name: readString(n.nameIndex),
    };
  });

  /* --- type definitions --- */
  const typeDefs = parseArray('typeDefinitionsOffset', 'typeDefinitionsSize', gatedSize(TYPE_DEF_FIELDS, vf), 'typeDefinitions', (dv, base, i) => {
    const t = readGated(dv, base, TYPE_DEF_FIELDS, vf, i);
    return {
      index: i,
      nameIndex: t.nameIndex,
      namespaceIndex: t.namespaceIndex,
      name: readString(t.nameIndex),
      namespace: readString(t.namespaceIndex),
      byvalTypeIndex: t.byvalTypeIndex,
      byrefTypeIndex: t.byrefTypeIndex,
      declaringTypeIndex: t.declaringTypeIndex,
      parentIndex: t.parentIndex,
      elementTypeIndex: t.elementTypeIndex,
      genericContainerIndex: t.genericContainerIndex,
      flags: t.flags,
      fieldStart: t.fieldStart,
      methodStart: t.methodStart,
      eventStart: t.eventStart,
      propertyStart: t.propertyStart,
      nestedTypesStart: t.nestedTypesStart,
      interfacesStart: t.interfacesStart,
      vtableMethodsStart: t.vtableMethodsStart,
      interfaceOffsetsStart: t.interfaceOffsetsStart,
      method_count: t.method_count,
      property_count: t.property_count,
      field_count: t.field_count,
      event_count: t.event_count,
      nested_type_count: t.nested_type_count,
      vtable_method_count: t.vtable_method_count,
      interfaces_count: t.interfaces_count,
      interface_offsets_count: t.interface_offsets_count,
      bitfield: t.bitfield,
      token: t.token,
    };
  });

  /* image index per type def */
  const typeImageIndex = new Int32Array(typeDefs.length).fill(-1);
  for (let ii = 0; ii < images.length; ii++) {
    const img = images[ii];
    if (img.typeStart === undefined || img.typeCount === undefined) continue;
    for (let i = 0; i < img.typeCount; i++) {
      const ti = img.typeStart + i;
      if (ti >= 0 && ti < typeDefs.length && typeImageIndex[ti] === -1) typeImageIndex[ti] = ii;
    }
  }
  for (let i = 0; i < typeDefs.length; i++) {
    if (typeImageIndex[i] === -1) {
      const declaring = typeDefs[i].declaringTypeIndex;
      if (declaring >= 0 && declaring < typeDefs.length && typeImageIndex[declaring] !== -1) {
        typeImageIndex[i] = typeImageIndex[declaring];
      }
    }
  }
  let unknownImages = 0;
  for (let i = 0; i < typeDefs.length; i++) {
    if (typeImageIndex[i] === -1) unknownImages++;
  }
  if (unknownImages > 0) warnings.push(`${unknownImages} type definitions could not be attributed to any image.`);

  /* --- methods --- */
  const methodDefs = parseArray('methodsOffset', 'methodsSize', gatedSize(METHOD_DEF_FIELDS, vf), 'methods', (dv, base, i) => {
    const m = readGated(dv, base, METHOD_DEF_FIELDS, vf, i);
    return {
      index: i,
      nameIndex: m.nameIndex,
      name: readString(m.nameIndex),
      declaringType: m.declaringType,
      returnType: m.returnType,
      returnParameterToken: m.returnParameterToken,
      parameterStart: m.parameterStart,
      genericContainerIndex: m.genericContainerIndex,
      token: m.token,
      flags: m.flags,
      iflags: m.iflags,
      slot: m.slot,
      parameterCount: m.parameterCount,
      param: [],
    };
  });

  /* --- fields, parameters, events, properties --- */
  const parameterDefs = parseArray('parametersOffset', 'parametersSize', gatedSize(PARAMETER_DEF_FIELDS, vf), 'parameters', (dv, base, i) => {
    const p = readGated(dv, base, PARAMETER_DEF_FIELDS, vf, i);
    return { index: i, nameIndex: p.nameIndex, name: readString(p.nameIndex), token: p.token, typeIndex: p.typeIndex };
  });

  const fieldDefs = parseArray('fieldsOffset', 'fieldsSize', gatedSize(FIELD_DEF_FIELDS, vf), 'fields', (dv, base, i) => {
    const f = readGated(dv, base, FIELD_DEF_FIELDS, vf, i);
    return { index: i, nameIndex: f.nameIndex, name: readString(f.nameIndex), typeIndex: f.typeIndex, token: f.token };
  });

  const propertyDefs = parseArray('propertiesOffset', 'propertiesSize', gatedSize(PROPERTY_DEF_FIELDS, vf), 'properties', (dv, base, i) => {
    const p = readGated(dv, base, PROPERTY_DEF_FIELDS, vf, i);
    return { index: i, name: readString(p.nameIndex), nameIndex: p.nameIndex, get: p.get, set: p.set, attrs: p.attrs, token: p.token };
  });

  const eventDefs = parseArray('eventsOffset', 'eventsSize', gatedSize(EVENT_DEF_FIELDS, vf), 'events', (dv, base, i) => {
    const e = readGated(dv, base, EVENT_DEF_FIELDS, vf, i);
    return { index: i, name: readString(e.nameIndex), nameIndex: e.nameIndex, typeIndex: e.typeIndex, add: e.add, remove: e.remove, raise: e.raise, token: e.token };
  });

  /* --- generic containers / parameters --- */
  const genericContainers = parseArray('genericContainersOffset', 'genericContainersSize', 16, 'genericContainers', (dv, base, i) => {
    return {
      index: i,
      ownerIndex: readU32LE(dv, base + i * 16),
      type_argc: readU32LE(dv, base + i * 16 + 4),
      is_method: readU32LE(dv, base + i * 16 + 8),
      genericParameterStart: readU32LE(dv, base + i * 16 + 12),
    };
  });

  const genericParameters = parseArray('genericParametersOffset', 'genericParametersSize', 16, 'genericParameters', (dv, base, i) => {
    const nameIndex = readU32LE(dv, base + i * 16 + 4);
    return {
      index: i,
      ownerIndex: readU32LE(dv, base + i * 16),
      nameIndex,
      name: readString(nameIndex),
      constraintsStart: readU32LE(dv, base + i * 16 + 8) & 0xffff,
      constraintsCount: readU32LE(dv, base + i * 16 + 10) & 0xffff,
      num: readU32LE(dv, base + i * 16 + 12) & 0xffff,
      flags: readU32LE(dv, base + i * 16 + 14) & 0xffff,
    };
  });

  /* --- default values --- */
  const parameterDefaultValues = parseArray('parameterDefaultValuesOffset', 'parameterDefaultValuesSize', 12, 'parameterDefaultValues', (dv, base, i) => {
    return { parameterIndex: readU32LE(dv, base + i * 12), typeIndex: readU32LE(dv, base + i * 12 + 4), dataIndex: readU32LE(dv, base + i * 12 + 8) };
  });
  const fieldDefaultValues = parseArray('fieldDefaultValuesOffset', 'fieldDefaultValuesSize', 12, 'fieldDefaultValues', (dv, base, i) => {
    return { fieldIndex: readU32LE(dv, base + i * 12), typeIndex: readU32LE(dv, base + i * 12 + 4), dataIndex: readU32LE(dv, base + i * 12 + 8) };
  });

  /* --- attribute data ranges --- */
  const ATTR_RANGE_FIELDS = [
    ['token', 4, 24.1, null],
    ['startOffset', 4],
    ['count', 4],
  ];
  const attributeDataRanges = parseArray('attributeDataRangeOffset', 'attributeDataRangeSize', gatedSize(ATTR_RANGE_FIELDS, vf), 'attributeDataRanges', (dv, base, i) => {
    const r = readGated(dv, base, ATTR_RANGE_FIELDS, vf, i);
    return { index: i, token: r.token, startOffset: r.startOffset, count: r.count };
  });

  /* --- field refs / interfaces / nested types --- */
  const fieldRefs = parseArray('fieldRefsOffset', 'fieldRefsSize', 8, 'fieldRefs', (dv, base, i) => {
    return { typeIndex: readU32LE(dv, base + i * 8), fieldIndex: readU32LE(dv, base + i * 8 + 4) };
  });
  const interfacesArr = parseArray('interfacesOffset', 'interfacesSize', 4, 'interfaces', (dv, base, i) => readU32LE(dv, base + i * 4));
  const nestedTypesArr = parseArray('nestedTypesOffset', 'nestedTypesSize', 4, 'nestedTypes', (dv, base, i) => readU32LE(dv, base + i * 4));

  /* --- link methods to params --- */
  for (const m of methodDefs) {
    if (m.parameterStart === undefined || m.parameterCount === undefined) continue;
    if (m.parameterStart < 0 || m.parameterStart + m.parameterCount > parameterDefs.length) {
      warnings.push(`Method ${m.name} (index ${m.index}) has out-of-range parameter range.`);
      continue;
    }
    m.param = parameterDefs.slice(m.parameterStart, m.parameterStart + m.parameterCount);
  }

  /* --- binary analysis --- */
  let bin = null;
  if (binary) {
    try {
      bin = new BinaryFile(binary, warnings);
    } catch (e) {
      warnings.push('Failed to parse binary: ' + e.message);
    }
  }
  info.binaryType = bin ? (bin.isPE ? 'PE' : bin.isELF ? 'ELF' : 'unknown') : null;
  info.is64 = bin ? bin.is64 : null;
  info.pointerSize = bin ? bin.pointerSize : null;
  info.imageBase = bin ? bin.imageBase : null;

  const result = {
    ok: true,
    info,
    sections,
    warnings: warnings.get(),
    stringLiterals,
    assemblies,
    images,
    typeDefs,
    methodDefs,
    fieldDefs,
    parameterDefs,
    propertyDefs,
    eventDefs,
    genericContainers,
    genericParameters,
    parameterDefaultValues,
    fieldDefaultValues,
    attributeDataRanges,
    fieldRefs,
    interfaces: interfacesArr,
    nestedTypes: nestedTypesArr,
    typeImageIndex: Array.from(typeImageIndex),
    methodAddresses: new Map(),
    fieldOffsets: [],
    binary: bin,
    modules: new Map(),
    typesArray: null,
  };

  /* --- metadata registration search (binary types + field offsets) --- */
  if (bin) {
    const reg = searchMetadataRegistration(bin, result, vf, warnings);
    if (reg) {
      result.registration = reg;
      result.typesArray = parseTypesArray(bin, reg);
      result.fieldOffsets = parseFieldOffsets(bin, reg, result, vf, warnings);
    } else {
      warnings.push('Could not locate the metadata registration (types/field offsets). Type signatures will be best-effort.');
    }
  }

  /* --- codegen modules (method addresses) --- */
  if (bin) {
    result.modules = findCodeGenModules(bin, result, warnings);
    resolveMethodAddresses(result, warnings);
  }

  buildDumps(result);

  return {
    ok: true,
    info: result.info,
    sections: result.sections,
    warnings: result.warnings,
    stringLiterals: result.stringLiterals,
    assemblies: result.assemblies,
    images: result.images,
    typeDefs: result.typeDefs,
    methodDefs: result.methodDefs,
    fieldDefs: result.fieldDefs,
    parameterDefs: result.parameterDefs,
    propertyDefs: result.propertyDefs,
    eventDefs: result.eventDefs,
    genericContainers: result.genericContainers,
    genericParameters: result.genericParameters,
    parameterDefaultValues: result.parameterDefaultValues,
    fieldDefaultValues: result.fieldDefaultValues,
    attributeDataRanges: result.attributeDataRanges,
    fieldRefs: result.fieldRefs,
    typeImageIndex: result.typeImageIndex,
    methodAddresses: result.methodAddresses,
    fieldOffsets: result.fieldOffsets,
    dumpCs: result.dumpCs,
    stringsDump: result.stringsDump,
    jsonDump: result.jsonDump,
    methodTableDump: result.methodTableDump,
    modules: result.modules,
    typesArrayCount: result.typesArray ? result.typesArray.length : 0,
  };
}

/* ------------------------------------------------------------------ */
/* Metadata registration search                                        */
/* ------------------------------------------------------------------ */

function registrationLayoutCandidates(version) {
  const cands = [];
  const typeDefSizesPair = 2;
  const fieldOffsetsPair = 1;
  const typesPairs = new Set([7]);
  if (isVersionAtLeast(version, 31)) typesPairs.add(5);
  if (!isVersionAtLeast(version, 29)) typesPairs.add(6);
  for (const ptrFirst of [true, false]) {
    for (const typesPair of typesPairs) {
      const idx = (pair, isCount) => ptrFirst ? pair * 2 + (isCount ? 1 : 0) : pair * 2 + (isCount ? 0 : 1);
      for (const totalPairs of [typesPair + 1, typesPair + 2]) {
        cands.push({
          ptrFirst,
          totalPairs,
          typesPair,
          typeDefSizesCountIdx: idx(typeDefSizesPair, true),
          fieldOffsetsCountIdx: idx(fieldOffsetsPair, true),
          fieldOffsetsPtrIdx: idx(fieldOffsetsPair, false),
          typeDefinitionsSizesPtrIdx: idx(typeDefSizesPair, false),
          typesPtrIdx: idx(typesPair, false),
          typesCountIdx: idx(typesPair, true),
          countRoleIdx: [idx(typeDefSizesPair, true), idx(fieldOffsetsPair, true), idx(typesPair, true)],
        });
      }
    }
  }
  return cands;
}

function searchMetadataRegistration(bin, result, version, warnings) {
  const typeDefsCount = result.typeDefs.length;
  if (typeDefsCount <= 0) return null;
  const ptrSize = bin.pointerSize;
  const candidates = registrationLayoutCandidates(version);
  const u32 = new Uint32Array(bin.buffer);
  const wordBytes = ptrSize / 4;
  const limit = Math.max(0, u32.length - wordBytes + 1);
  const tried = new Set();

  for (let i = 0; i < limit; i += wordBytes) {
    if (u32[i] !== typeDefsCount) continue;
    if (!bin.isMappedFileOffset(i * 4)) continue;
    const pos = i * 4;
    for (const layout of candidates) {
      const mrSize = layout.totalPairs * 2 * ptrSize;
      for (const roleIdx of layout.countRoleIdx) {
        const start = pos - roleIdx * ptrSize;
        if (start < 0 || start + mrSize > bin.buffer.byteLength) continue;
        const key = layout.ptrFirst + '|' + layout.totalPairs + '|' + layout.typesPair + '|' + roleIdx + '|' + start;
        if (tried.has(key)) continue;
        tried.add(key);
        const reg = validateRegistration(bin, start, layout, typeDefsCount, ptrSize);
        if (reg) {
          warnings.push(`Metadata registration found at VA 0x${(bin.fileOffsetToVa(start) >>> 0).toString(16)} (types at pair ${layout.typesPair}, ${layout.ptrFirst ? 'ptr-first' : 'count-first'} order).`);
          return { ...reg, ...layout, start };
        }
      }
    }
  }
  return null;
}

function validateRegistration(bin, start, layout, typeDefsCount, ptrSize) {
  const dv = bin.dv;
  const nFields = layout.totalPairs * 2;
  if (start < 0 || start + nFields * ptrSize > dv.byteLength) return null;
  const fields = [];
  for (let i = 0; i < nFields; i++) {
    const v = ptrSize === 8 ? readU64LE(dv, start + i * ptrSize) : readU32LE(dv, start + i * ptrSize);
    if (v === undefined) return null;
    fields.push(v);
  }
  const typeDefSizesCount = fields[layout.typeDefSizesCountIdx];
  const fieldOffsetsCount = fields[layout.fieldOffsetsCountIdx];
  const typesCount = fields[layout.typesCountIdx];
  const typesPtr = fields[layout.typesPtrIdx];
  if (typeDefSizesCount !== typeDefsCount) return null;
  if (fieldOffsetsCount !== typeDefsCount) return null;
  if (typesCount === undefined || typesCount < typeDefsCount) return null;
  if (typesCount > typeDefsCount * 8 + 100000) return null;
  if (typesPtr === undefined || typesPtr === 0) return null;
  if (bin.vaToFileOffset(typesPtr) < 0) return null;
  const isPtrField = (i) => layout.ptrFirst ? i % 2 === 0 : i % 2 === 1;
  for (let i = 0; i < nFields; i++) {
    const v = fields[i];
    if (v < 0 || v > Number.MAX_SAFE_INTEGER) return null;
    if (v === 0) continue;
    if (isPtrField(i)) {
      if (bin.vaToFileOffset(v) < 0) return null;
    } else {
      if (v > 1 << 26) return null;
    }
  }
  return {
    typesCount,
    types: typesPtr,
    fieldOffsetsCount,
    fieldOffsets: fields[layout.fieldOffsetsPtrIdx],
    typeDefinitionsSizes: fields[layout.typeDefinitionsSizesPtrIdx],
  };
}

function parseTypesArray(bin, reg) {
  const ptrSize = bin.pointerSize;
  const count = reg.typesCount;
  const size = ptrSize + 4;
  const arr = new Array(count);
  for (let i = 0; i < count; i++) {
    const ptr = bin.readPtrAtVa(reg.types + i * ptrSize);
    if (ptr < 0) {
      arr[i] = null;
      continue;
    }
    const off = bin.vaToFileOffset(ptr);
    if (off < 0 || off + size > bin.dv.byteLength) {
      arr[i] = null;
      continue;
    }
    arr[i] = {
      data: bin.pointerSize === 8 ? readU64LE(bin.dv, off) : readU32LE(bin.dv, off),
      bits: readU32LE(bin.dv, off + bin.pointerSize),
    };
  }
  return arr;
}

function parseFieldOffsets(bin, reg, result, version, warnings) {
  const ptrSize = bin.pointerSize;
  const count = reg.fieldOffsetsCount;
  const out = new Array(count).fill(null);
  const arePointers = isVersionAtLeast(version, 22);
  const arrayBaseVA = reg.fieldOffsets;
  if (arrayBaseVA === 0) return out;
  let ok = 0;
  for (let i = 0; i < count; i++) {
    const typeDef = result.typeDefs[i];
    const fieldCount = typeDef && typeDef.field_count !== undefined ? typeDef.field_count : 0;
    let arrVA;
    if (arePointers) {
      arrVA = bin.readPtrAtVa(arrayBaseVA + i * ptrSize);
      if (arrVA <= 0) continue;
    } else {
      arrVA = arrayBaseVA + i * fieldCount * 4;
    }
    const arrOff = bin.vaToFileOffset(arrVA);
    if (arrOff < 0) continue;
    const vals = [];
    let bad = false;
    for (let k = 0; k < fieldCount; k++) {
      const v = readU32LE(bin.dv, arrOff + k * 4);
      if (v === undefined) {
        bad = true;
        break;
      }
      vals.push(v);
    }
    if (!bad) {
      out[i] = vals;
      ok++;
    }
  }
  if (ok === 0 && count > 0) warnings.push('Field offsets could not be resolved from the binary.');
  return out;
}

/* ------------------------------------------------------------------ */
/* Codegen module discovery + method addresses                         */
/* ------------------------------------------------------------------ */

function findBytes(haystack, needle, from) {
  const n = needle.length;
  if (n === 0 || from < 0) return -1;
  const last = haystack.length - n;
  for (let i = Math.max(0, from); i <= last; i++) {
    if (haystack[i] !== needle[0]) continue;
    let j = 1;
    while (j < n && haystack[i + j] === needle[j]) j++;
    if (j === n) return i;
  }
  return -1;
}

function findCodeGenModules(bin, result, warnings) {
  const modules = new Map();
  const ptrSize = bin.pointerSize;
  const u8 = new Uint8Array(bin.buffer);
  const u32 = new Uint32Array(bin.buffer);
  const wordBytes = ptrSize / 4;
  const limit = Math.max(0, u32.length - wordBytes + 1);

  const collectPointersTo = (va) => {
    if (va < 0) return [];
    const lo = va % 0x100000000;
    const hi = Math.floor(va / 0x100000000);
    const hits = [];
    for (let i = 0; i < limit; i += wordBytes) {
      if (!bin.isMappedFileOffset(i * 4)) continue;
      if (u32[i] !== lo) continue;
      if (ptrSize === 8 && u32[i + 1] !== hi) continue;
      hits.push(i * 4);
    }
    return hits;
  };

  const validateModule = (structStart) => {
    if (structStart + ptrSize * 3 > bin.dv.byteLength) return null;
    const namePtr = ptrSize === 8 ? readU64LE(bin.dv, structStart) : readU32LE(bin.dv, structStart);
    const count = ptrSize === 8 ? readU64LE(bin.dv, structStart + ptrSize) : readU32LE(bin.dv, structStart + ptrSize);
    const ptrs = ptrSize === 8 ? readU64LE(bin.dv, structStart + ptrSize * 2) : readU32LE(bin.dv, structStart + ptrSize * 2);
    if (namePtr === undefined || count === undefined || ptrs === undefined) return null;
    if (count < 0 || count > 20000000) return null;
    if (namePtr === 0 || ptrs === 0) return null;
    const nameOff = bin.vaToFileOffset(namePtr);
    if (nameOff < 0) return null;
    const name = readAscii(bin.dv, nameOff, 300);
    if (!name || name.length > 260 || !/^[\w.\-+ ]{1,260}$/i.test(name)) return null;
    const ptrsOff = bin.vaToFileOffset(ptrs);
    if (ptrsOff < 0) return null;
    if (count > 0 && ptrsOff + count * ptrSize > bin.dv.byteLength) return null;
    let valid = 0;
    const sampleN = Math.min(count, 64);
    for (let k = 0; k < sampleN; k++) {
      const pv = ptrSize === 8 ? readU64LE(bin.dv, ptrsOff + k * ptrSize) : readU32LE(bin.dv, ptrsOff + k * ptrSize);
      if (pv === undefined || pv === 0) continue;
      if (bin.vaToFileOffset(pv) >= 0) valid++;
    }
    if (count > 0 && valid < Math.max(1, Math.floor(sampleN * 0.5))) return null;
    return { name, methodPointerCount: count, methodPointers: ptrs, methodPointersOff: ptrsOff, structStart };
  };

  for (const img of result.images) {
    if (!img.name) continue;
    const needle = new Uint8Array(img.name.length + 1);
    for (let k = 0; k < img.name.length; k++) needle[k] = img.name.charCodeAt(k) & 0xff;
    let idx = -1;
    let found = null;
    while (!found) {
      idx = findBytes(u8, needle, idx + 1);
      if (idx < 0) break;
      if (!bin.isMappedFileOffset(idx)) continue;
      const strVA = bin.fileOffsetToVa(idx);
      if (strVA < 0) continue;
      const hits = collectPointersTo(strVA);
      for (const h of hits) {
        const mod = validateModule(h);
        if (mod) {
          found = mod;
          break;
        }
      }
    }
    if (found) modules.set(img.name, found);
  }

  if (modules.size === 0) {
    warnings.push('No codegen modules found via image names. Method addresses will be unavailable.');
  } else if (modules.size < result.images.length) {
    warnings.push(`Found ${modules.size} of ${result.images.length} images as codegen modules; some method addresses will be missing.`);
  }
  return modules;
}

function resolveMethodAddresses(result, warnings) {
  const bin = result.binary;
  const map = result.methodAddresses;
  const ptrSize = bin.pointerSize;
  let resolved = 0;
  let skipped = 0;
  for (const td of result.typeDefs) {
    const imgIdx = result.typeImageIndex[td.index];
    if (imgIdx < 0 || imgIdx >= result.images.length) continue;
    const module = result.modules.get(result.images[imgIdx].name);
    if (!module) continue;
    if (td.methodStart === undefined || td.method_count === undefined) continue;
    for (let k = 0; k < td.method_count; k++) {
      const m = result.methodDefs[td.methodStart + k];
      if (!m) continue;
      const rid = m.token !== undefined ? (m.token & 0xffffff) : 0;
      if (rid < 1 || rid > module.methodPointerCount) {
        skipped++;
        continue;
      }
      const off = module.methodPointersOff + (rid - 1) * ptrSize;
      const ptr = ptrSize === 8 ? readU64LE(bin.dv, off) : readU32LE(bin.dv, off);
      if (ptr === undefined || ptr === 0) {
        skipped++;
        continue;
      }
      const rva = bin.isPE ? ptr - bin.imageBase : -1;
      const fileOffset = bin.vaToFileOffset(ptr);
      map.set(m.index, {
        name: m.name,
        token: m.token,
        image: result.images[imgIdx].name,
        va: ptr,
        rva: rva >= 0 ? rva : -1,
        fileOffset,
      });
      resolved++;
    }
  }
  if (resolved === 0 && map.size === 0) {
    warnings.push('Method addresses could not be resolved (codegen modules found but no valid mappings).');
  }
  if (skipped > 0) warnings.push(`${skipped} method tokens were outside the codegen methodPointerCount range.`);
}

/* ------------------------------------------------------------------ */
/* Type name resolution                                                */
/* ------------------------------------------------------------------ */

function buildTypeResolvers(result) {
  const byvalToTypeDef = new Map();
  const byrefToTypeDef = new Map();
  for (const td of result.typeDefs) {
    if (td.byvalTypeIndex !== undefined && td.byvalTypeIndex >= 0) {
      if (!byvalToTypeDef.has(td.byvalTypeIndex)) byvalToTypeDef.set(td.byvalTypeIndex, td.index);
    }
    if (td.byrefTypeIndex !== undefined && td.byrefTypeIndex >= 0) {
      if (!byrefToTypeDef.has(td.byrefTypeIndex)) byrefToTypeDef.set(td.byrefTypeIndex, td.index);
    }
  }
  const typeDefName = (idx) => {
    const td = result.typeDefs[idx];
    if (!td) return null;
    if (td.declaringTypeIndex >= 0) {
      const outer = typeDefName(td.declaringTypeIndex);
      if (outer) return outer + '/' + td.name;
    }
    return td.namespace ? td.namespace + '.' + td.name : td.name;
  };
  const typeDefGeneric = (idx) => {
    const td = result.typeDefs[idx];
    if (!td || td.genericContainerIndex === undefined || td.genericContainerIndex < 0) return '';
    const c = result.genericContainers[td.genericContainerIndex];
    if (!c || !c.type_argc) return '';
    const names = [];
    for (let i = 0; i < c.type_argc; i++) {
      const gp = result.genericParameters[c.genericParameterStart + i];
      names.push(gp ? gp.name : 'T' + i);
    }
    return '<' + names.join(', ') + '>';
  };
  return { byvalToTypeDef, byrefToTypeDef, typeDefName, typeDefGeneric };
}

function methodGenericsOf(result, m) {
  if (!m || m.genericContainerIndex === undefined || m.genericContainerIndex < 0) return null;
  const c = result.genericContainers[m.genericContainerIndex];
  if (!c || !c.type_argc) return null;
  const names = [];
  for (let i = 0; i < c.type_argc; i++) {
    const gp = result.genericParameters[c.genericParameterStart + i];
    names.push(gp ? gp.name : 'T' + i);
  }
  return names;
}

function resolveTypeIndex(result, resolvers, typeIndex, context, depth) {
  if (typeIndex === undefined || typeIndex < 0) return '?';
  depth = depth || 0;
  if (depth > 16) return '?';
  if (result.typesArray && typeIndex < result.typesArray.length) {
    const t = result.typesArray[typeIndex];
    if (t) return resolveBinaryType(result, resolvers, t, typeIndex, context, depth);
  }
  const tdIdx = resolvers.byvalToTypeDef.get(typeIndex);
  if (tdIdx !== undefined) {
    return resolvers.typeDefName(tdIdx) + resolvers.typeDefGeneric(tdIdx);
  }
  const tdIdx2 = resolvers.byrefToTypeDef.get(typeIndex);
  if (tdIdx2 !== undefined) return resolvers.typeDefName(tdIdx2) + '&';
  const prim = PRIMITIVE_NAMES[typeIndex];
  if (prim) return prim.toLowerCase();
  return '?t' + typeIndex;
}

function resolveBinaryType(result, resolvers, t, typeIndex, context, depth) {
  const bits = t.bits;
  const kind = (bits >>> 16) & 0xff;
  const data = t.data;
  const bin = result.binary;
  const getTypeAtPtr = (ptr, ctx) => {
    if (!bin) return '?';
    const off = bin.vaToFileOffset(ptr);
    if (off < 0 || off + bin.pointerSize + 4 > bin.dv.byteLength) return '?';
    const sub = {
      data: bin.pointerSize === 8 ? readU64LE(bin.dv, off) : readU32LE(bin.dv, off),
      bits: readU32LE(bin.dv, off + bin.pointerSize),
    };
    return resolveBinaryType(result, resolvers, sub, -1, ctx, depth + 1);
  };
  const typeDefIndex = Number(data);
  switch (kind) {
    case 1: return 'void';
    case 2: return 'bool';
    case 3: return 'char';
    case 4: return 'sbyte';
    case 5: return 'byte';
    case 6: return 'short';
    case 7: return 'ushort';
    case 8: return 'int';
    case 9: return 'uint';
    case 10: return 'long';
    case 11: return 'ulong';
    case 12: return 'float';
    case 13: return 'double';
    case 14: return 'string';
    case 15: return getTypeAtPtr(data, context) + '*';
    case 16: return getTypeAtPtr(data, context) + '*';
    case 17: return getTypeAtPtr(data, context) + '&';
    case 18:
    case 19: {
      const name = resolvers.typeDefName(typeDefIndex);
      const g = resolvers.typeDefGeneric(typeDefIndex);
      if (name) return name + g;
      return '?t' + typeIndex;
    }
    case 20: {
      const gp = result.genericParameters[typeDefIndex];
      return gp ? gp.name : 'T?';
    }
    case 21:
    case 22: {
      const inner = getTypeAtPtr(data, context);
      return inner === '?' ? '[]?' : inner + '[]';
    }
    case 23: {
      if (!bin) return '?';
      const off = bin.vaToFileOffset(data);
      if (off < 0) return '?';
      const argc = readU32LE(bin.dv, off);
      const argv = bin.pointerSize === 8 ? readU64LE(bin.dv, off + 8) : readU32LE(bin.dv, off + 4);
      if (argc === undefined || argv === undefined || argc <= 0 || argc > 64) return '?';
      const readTypePtr = (p) => {
        const pOff = bin.vaToFileOffset(p);
        if (pOff < 0) return null;
        return {
          data: bin.pointerSize === 8 ? readU64LE(bin.dv, pOff) : readU32LE(bin.dv, pOff),
          bits: readU32LE(bin.dv, pOff + bin.pointerSize),
        };
      };
      const first = readTypePtr(argv);
      let base = '?';
      if (first) base = resolveBinaryType(result, resolvers, first, -1, context, depth + 1);
      const args = [];
      for (let i = 1; i < argc; i++) {
        const sub = readTypePtr(argv + i * bin.pointerSize);
        args.push(sub ? resolveBinaryType(result, resolvers, sub, -1, context, depth + 1) : '?');
      }
      return base + '<' + args.join(', ') + '>';
    }
    case 24: return 'typedbyref';
    case 25: return 'IntPtr';
    case 26: return 'UIntPtr';
    case 27: return 'delegate*<void>';
    case 28: return 'object';
    case 29: {
      const inner = getTypeAtPtr(data, context);
      return inner === '?' ? '[]?' : inner + '[]';
    }
    case 30: {
      const mg = context && context.methodGenerics ? context.methodGenerics : null;
      return mg && typeDefIndex >= 0 && typeDefIndex < mg.length ? mg[typeDefIndex] : 'M?' + typeDefIndex;
    }
    default: {
      const prim = PRIMITIVE_NAMES[kind];
      return prim ? prim.toLowerCase() : '?k' + kind;
    }
  }
}

/* ------------------------------------------------------------------ */
/* Output dumps                                                        */
/* ------------------------------------------------------------------ */

function methodModifiers(m) {
  const s = [];
  const flags = m.flags;
  if ((flags & 0x10) !== 0) s.push('static');
  if ((flags & 0x40) !== 0) s.push('virtual');
  if ((flags & 0x400) !== 0) s.push('abstract');
  if ((flags & 0x20) !== 0) s.push('final');
  if ((flags & 0x800) !== 0) s.push('specialname');
  return s.join(' ');
}

function fieldModifiers(f) {
  const s = [];
  const flags = f.flags;
  if ((flags & 0x10) !== 0) s.push('static');
  if ((flags & 0x40) !== 0) s.push('literal');
  if ((flags & 0x20) !== 0) s.push('initonly');
  return s.join(' ');
}

function buildDumps(result) {
  const resolvers = buildTypeResolvers(result);
  const lines = [];
  const stringSet = new Set();
  const methodEntries = [];

  lines.push('// Metadata Dump');
  lines.push(`// Unity: ${result.info.versionLabel} (metadata v${result.info.version})`);
  lines.push(`// Header at 0x${result.info.headerOffset.toString(16)}, magic ${result.info.magicHex}${result.info.stripped ? ' (stripped)' : ''}`);
  lines.push(`// Images: ${result.images.length}  Types: ${result.typeDefs.length}  Methods: ${result.methodDefs.length}`);
  if (result.methodAddresses.size > 0) {
    lines.push(`// Resolved method addresses: ${result.methodAddresses.size}`);
  } else {
    lines.push('// Method addresses: none (no binary or no codegen modules found)');
  }
  lines.push('');

  const defaultByField = new Map();
  for (const fd of result.fieldDefaultValues) {
    if (fd.fieldIndex !== undefined) defaultByField.set(fd.fieldIndex, fd);
  }

  const constValue = (fdv) => {
    if (!fdv || fdv.dataIndex === undefined) return null;
    const base = result.sections.fieldAndParameterDefaultValueDataOffset;
    if (base === undefined || base < 0) return null;
    const idx = fdv.dataIndex;
    const typeIdx = fdv.typeIndex;
    if (typeIdx === undefined || typeIdx < 0) return null;
    const dv = result.binary ? result.binary.dv : null;
    if (!dv) return null;
    const t = result.typesArray && typeIdx < result.typesArray.length ? result.typesArray[typeIdx] : null;
    if (!t) return null;
    const kind = (t.bits >>> 16) & 0xff;
    try {
      switch (kind) {
        case 2: return String(Boolean(dv.getUint8(base + idx)));
        case 3: return "'" + String.fromCharCode(dv.getUint16(base + idx, true)) + "'";
        case 4: return String(dv.getInt8(base + idx));
        case 5: return String(dv.getUint8(base + idx));
        case 6: return String(dv.getInt16(base + idx, true));
        case 7: return String(dv.getUint16(base + idx, true));
        case 8: return String(dv.getInt32(base + idx, true));
        case 9: return String(dv.getUint32(base + idx, true));
        case 10: return dv.getBigInt64 ? String(Number(dv.getBigInt64(base + idx, true))) : String(dv.getInt32(base + idx, true));
        case 11: return dv.getBigUint64 ? String(Number(dv.getBigUint64(base + idx, true))) : String(dv.getUint32(base + idx, true));
        case 12: return String(dv.getFloat32(base + idx, true));
        case 13: return String(dv.getFloat64(base + idx, true));
        case 14: {
          const len = dv.getUint32(base + idx, true);
          if (len > 65536) return null;
          let s = '"';
          for (let i = 0; i < len; i++) {
            const c = dv.getUint8(base + idx + 4 + i);
            s += c === 0 ? '' : String.fromCharCode(c);
          }
          return s + '"';
        }
        default: return null;
      }
    } catch {
      return null;
    }
  };

  const paramStr = (m) => {
    const ps = [];
    for (let i = 0; i < m.param.length; i++) {
      const p = m.param[i];
      const ctx = { typeDef: m.declaringType, method: m, methodGenerics: methodGenericsOf(result, m) };
      const tn = resolveTypeIndex(result, resolvers, p.typeIndex, ctx, 0);
      ps.push(tn + ' ' + (p.name || 'arg' + i));
    }
    return ps.join(', ');
  };

  const byImage = new Map();
  for (const td of result.typeDefs) {
    const imgIdx = result.typeImageIndex[td.index];
    const key = imgIdx >= 0 ? imgIdx : -1;
    if (!byImage.has(key)) byImage.set(key, []);
    byImage.get(key).push(td);
  }

  for (const [imgIdx, typeList] of byImage) {
    if (imgIdx >= 0 && imgIdx < result.images.length) {
      lines.push(`// Image: ${result.images[imgIdx].name}`);
    } else {
      lines.push('// Image: <unknown>');
    }
    const byNamespace = new Map();
    for (const td of typeList) {
      if (td.declaringTypeIndex >= 0) continue;
      if (!byNamespace.has(td.namespace)) byNamespace.set(td.namespace, []);
      byNamespace.get(td.namespace).push(td);
    }
    for (const [ns, tds] of byNamespace) {
      if (ns) lines.push(`namespace ${ns}`);
      if (ns) lines.push('{');
      const indent = ns ? '    ' : '';
      for (const td of tds) {
        const access = TYPE_ACCESS[(td.flags & 0x7) || 0] || 'private';
        const isStruct = td.bitfield !== undefined && ((td.bitfield >> 31) & 1) === 1;
        const baseName = td.parentIndex >= 0 ? resolvers.typeDefName(td.parentIndex) : null;
        const bases = [];
        if (baseName) bases.push(baseName);
        for (let i = 0; i < (td.interfaces_count || 0); i++) {
          const ti = result.interfaces[td.interfacesStart + i];
          if (ti !== undefined && ti >= 0) {
            const iname = resolvers.typeDefName(ti);
            if (iname) bases.push(iname);
          }
        }
        const genStr = resolvers.typeDefGeneric(td.index);
        const header = `${indent}${access} ${isStruct ? 'struct' : 'class'} ${td.name}${genStr}${bases.length ? ' : ' + bases.join(', ') : ''} // TypeDefIndex: ${td.index}, Token: ${td.token !== undefined ? hex(td.token) : 'n/a'}${td.byvalTypeIndex !== undefined ? ', TypeIndex: ' + td.byvalTypeIndex : ''}`;
        lines.push(header);
        lines.push(`${indent}{`);

        for (let fi = 0; fi < (td.field_count || 0); fi++) {
          const f = result.fieldDefs[td.fieldStart + fi];
          if (!f) continue;
          const ftn = resolveTypeIndex(result, resolvers, f.typeIndex, { typeDef: td, method: null }, 0);
          const fMods = f.flags !== undefined ? fieldModifiers(f) : '';
          const foff = result.fieldOffsets[td.index] ? result.fieldOffsets[td.index][fi] : undefined;
          const offStr = foff !== undefined ? '0x' + foff.toString(16) : null;
          const def = defaultByField.get(f.index);
          const constVal = def ? constValue(def) : null;
          lines.push(`${indent}    ${fMods ? fMods + ' ' : ''}${ftn} ${f.name}; // ${offStr ? 'Offset: ' + offStr + ', ' : ''}Token: ${f.token !== undefined ? hex(f.token) : 'n/a'}${constVal !== null ? ' = ' + constVal : ''}`);
        }

        for (let pi = 0; pi < (td.property_count || 0); pi++) {
          const p = result.propertyDefs[td.propertyStart + pi];
          if (!p) continue;
          let ptype = '?';
          let getterMods = '';
          if (p.get !== undefined && p.get >= 0 && p.get < result.methodDefs.length) {
            const gm = result.methodDefs[p.get];
            ptype = resolveTypeIndex(result, resolvers, gm.returnType, { typeDef: td, method: gm }, 0);
            const acc = METHOD_ACCESS[(gm.flags & 0x7) || 0] || '';
            getterMods = acc ? acc + ' ' : '';
            getterMods += methodModifiers(gm);
          } else if (p.set !== undefined && p.set >= 0 && p.set < result.methodDefs.length) {
            const sm = result.methodDefs[p.set];
            if (sm.param.length > 0) {
              ptype = resolveTypeIndex(result, resolvers, sm.param[sm.param.length - 1].typeIndex, { typeDef: td, method: sm }, 0);
            }
          }
          const getter = p.get !== undefined && p.get >= 0 ? 'get; ' : '';
          const setter = p.set !== undefined && p.set >= 0 ? 'set; ' : '';
          lines.push(`${indent}    ${getterMods}${ptype} ${p.name} { ${getter}${setter}} // Token: ${p.token !== undefined ? hex(p.token) : 'n/a'}`);
        }

        for (let ei = 0; ei < (td.event_count || 0); ei++) {
          const e = result.eventDefs[td.eventStart + ei];
          if (!e) continue;
          const etn = resolveTypeIndex(result, resolvers, e.typeIndex, { typeDef: td, method: null }, 0);
          lines.push(`${indent}    event ${etn} ${e.name} { add {} remove {} } // Token: ${e.token !== undefined ? hex(e.token) : 'n/a'}`);
        }

        for (let mi = 0; mi < (td.method_count || 0); mi++) {
          const m = result.methodDefs[td.methodStart + mi];
          if (!m) continue;
          const acc = METHOD_ACCESS[(m.flags & 0x7) || 0] || 'private';
          const mods = methodModifiers(m);
          const ctx = { typeDef: td, method: m, methodGenerics: methodGenericsOf(result, m) };
          const ret = resolveTypeIndex(result, resolvers, m.returnType, ctx, 0);
          const ps = paramStr(m);
          const addr = result.methodAddresses.get(m.index);
          let suffix = `Token: ${m.token !== undefined ? hex(m.token) : 'n/a'}`;
          if (addr) {
            suffix += `, RVA: 0x${addr.rva.toString(16)}, VA: 0x${addr.va.toString(16)}`;
            methodEntries.push({
              name: td.namespace ? td.namespace + '.' + td.name + '.' + m.name : td.name + '.' + m.name,
              methodIndex: m.index,
              typeIndex: td.index,
              image: addr.image,
              token: m.token,
              rva: addr.rva,
              va: addr.va,
              fileOffset: addr.fileOffset,
              ret,
              params: ps,
            });
          }
          const generics = ctx.methodGenerics ? '<' + ctx.methodGenerics.join(', ') + '>' : '';
          const line = `${indent}    ${acc}${mods ? ' ' + mods : ''} ${ret} ${m.name}${generics}(${ps}) { } // ${suffix}`;
          lines.push(line);
        }
        lines.push(`${indent}}`);
        if (ns) lines.push('}');
        lines.push('');
      }
    }
  }

  for (const sl of result.stringLiterals) {
    if (sl.value !== null && sl.value.length > 0) stringSet.add(sl.value);
  }

  result.dumpCs = lines.join('\n');
  result.stringsDump = Array.from(stringSet).join('\n');
  result.methodTableDump = methodEntries
    .map((m) => `${m.name}\t0x${m.rva.toString(16)}\t0x${m.va.toString(16)}\t0x${m.fileOffset.toString(16)}\t${m.token}\t${m.image}`)
    .join('\n');

  const jsonObj = {
    info: result.info,
    images: result.images.map((i) => ({ name: i.name, assemblyIndex: i.assemblyIndex, typeStart: i.typeStart, typeCount: i.typeCount, token: i.token })),
    assemblies: result.assemblies.map((a) => ({ name: a.name, imageIndex: a.imageIndex, token: a.token })),
    stringLiterals: result.stringLiterals.map((s) => ({ value: s.value })),
    types: result.typeDefs.map((td) => ({
      index: td.index,
      name: td.namespace ? td.namespace + '.' + td.name : td.name,
      namespace: td.namespace,
      flags: td.flags,
      token: td.token,
      image: result.typeImageIndex[td.index] >= 0 ? result.images[result.typeImageIndex[td.index]].name : null,
      parent: td.parentIndex,
      fieldCount: td.field_count,
      methodCount: td.method_count,
      propertyCount: td.property_count,
      eventCount: td.event_count,
    })),
    methods: result.methodDefs.map((m) => ({
      index: m.index,
      name: m.name,
      declaringType: m.declaringType,
      token: m.token,
      flags: m.flags,
      slot: m.slot,
      address: result.methodAddresses.get(m.index)
        ? { rva: result.methodAddresses.get(m.index).rva, va: result.methodAddresses.get(m.index).va, fileOffset: result.methodAddresses.get(m.index).fileOffset }
        : null,
    })),
    methodAddresses: methodEntries,
  };
  result.jsonDump = JSON.stringify(jsonObj, null, 2);
  result._resolvers = resolvers;
}
