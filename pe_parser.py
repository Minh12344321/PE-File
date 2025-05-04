import hashlib
import math
import pefile

# Tính toán entropy của dữ liệu
def calculate_entropy(data):
    if not data:
        return 0.0
    occurences = [0] * 256
    for x in data:
        occurences[x] += 1
    entropy = 0
    for count in occurences:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

# Phân tích DOS Header
def parse_dos_header(pe):
    dos_header_data = pe.__data__[:pe.DOS_HEADER.e_lfanew]
    sha256_hash = hashlib.sha256(dos_header_data).hexdigest()
    size = len(dos_header_data)
    location = f"0x00000000 - 0x{size:08X}"
    entropy = calculate_entropy(dos_header_data)
    full_size = len(pe.__data__)
    file_ratio = round((size / full_size) * 100, 2) if full_size else 0
    e_lfanew = pe.DOS_HEADER.e_lfanew
    return [
        ("dos-header > sha256", sha256_hash),
        ("size", f"0x{size:X} ({size} bytes)"),
        ("dos-header > location", location),
        ("entropy", entropy),
        ("file > ratio", f"{file_ratio} %"),
        ("exe-header > offset", f"0x{e_lfanew:08X} (e_lfanew)")
    ]

# Phân tích Sections Table
def parse_sections(pe):
    sections_info = []
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').rstrip('\x00')
        entropy = calculate_entropy(section.get_data())
        raw_start = section.PointerToRawData
        raw_end = raw_start + section.SizeOfRawData
        raw_address = f"0x{raw_start:08X} - 0x{raw_end:08X}"
        raw_size = f"{section.SizeOfRawData} bytes"
        virtual_address = f"0x{section.VirtualAddress:08X}"
        virtual_size = f"0x{section.Misc_VirtualSize:X} ({section.Misc_VirtualSize} bytes)"

        flags = []
        if section.Characteristics & 0x20000000: flags.append("Execute")
        if section.Characteristics & 0x40000000: flags.append("Read")
        if section.Characteristics & 0x80000000: flags.append("Write")
        if section.Characteristics & 0x00000020: flags.append("Code")
        if section.Characteristics & 0x00000040: flags.append("Uninitialized Data")
        if section.Characteristics & 0x00000080: flags.append("Initialized Data")

        characteristics = ", ".join(flags)

        sections_info.append((
            name,
            entropy,
            raw_address,
            raw_size,
            virtual_address,
            virtual_size,
            characteristics
        ))
    return sections_info

# Load danh sách API nghi vấn từ file
def load_suspicious_apis(file_path="suspicious_apis.txt"):
    try:
        with open(file_path, "r") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except:
        return set()

# Hàm parse chính
def parse_pe(file_path):
    data = {
        'DOS Header': [],
        'Sections Table': [],
        'Import Table': [],
        'Export Table': [],
        'Resource Table': [],
        'Relocation Table': [],
         'Library': [] 
    }

    try:
        pe = pefile.PE(file_path)

        # DOS HEADER
        data['DOS Header'] = parse_dos_header(pe)

        # SECTIONS TABLE
        data['Sections Table'] = parse_sections(pe)

        # IMPORT TABLE
        suspicious_apis = load_suspicious_apis()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                    ordinal = imp.ordinal if imp.ordinal else '-'
                    is_flagged = "❌" if func_name.lower() in suspicious_apis else ""
                    data['Import Table'].append((
                        func_name,
                        dll_name,
                        "implicit",
                        str(ordinal),
                        is_flagged
                    ))
        else:
            data['Import Table'].append(('N/A', '-', '-', '-', ''))

        # EXPORT TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                func_name = exp.name.decode('utf-8', errors='ignore') if exp.name else 'None'
                address = hex(exp.address) if isinstance(exp.address, int) else str(exp.address)
                data['Export Table'].append((
                    address,
                    '',
                    func_name
                ))
        else:
            data['Export Table'].append(('N/A', '', 'No exports found.'))

        # RESOURCE TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                name = (
                    str(resource_type.name)
                    if resource_type.name
                    else str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'Unknown'))
                )

                if hasattr(resource_type, 'directory'):
                    for entry in resource_type.directory.entries:
                        if hasattr(entry, 'directory'):
                            for lang_entry in entry.directory.entries:
                                data_rva = lang_entry.data.struct.OffsetToData
                                size = lang_entry.data.struct.Size
                                data_offset = pe.get_offset_from_rva(data_rva)
                                resource_data = pe.__data__[data_offset:data_offset + size]

                                sha256 = hashlib.sha256(resource_data).hexdigest()
                                entropy = calculate_entropy(resource_data)

                                offset = f"0x{data_offset:08X}"
                                data['Resource Table'].append((
                                    offset,
                                    sha256,
                                    entropy,
                                    name
                                ))
        else:
            data['Resource Table'].append(('N/A', '', '', 'No resources found.'))

        # LIBRARY
        libraries_set = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imp_count = len(entry.imports)
                libraries_set.add((dll_name, imp_count))
        data['Library'] = sorted(libraries_set)

        # RELOCATION TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for reloc in base_reloc.entries:
                    rva = hex(reloc.rva)
                    reloc_type = reloc.type
                    data['Relocation Table'].append((
                        rva,
                        '',
                        f"Type: {reloc_type}"
                    ))
        else:
            data['Relocation Table'].append(('N/A', '', 'No relocation entries.'))

    except Exception as e:
        print(f"Error parsing PE file: {e}")

    return data
       
