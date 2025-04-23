import hashlib
import math
import pefile

# Hàm tính toán entropy
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

# Hàm phân tích DOS Header
def parse_dos_header(pe):
    dos_header_data = pe.__data__[:pe.DOS_HEADER.e_lfanew]  # từ 0 -> e_lfanew
    sha256_hash = hashlib.sha256(dos_header_data).hexdigest()

    size = len(dos_header_data)          # Số byte
    location = f"0x00000000 - 0x{size:08X}"

    # Tính entropy
    entropy = calculate_entropy(dos_header_data)

    # Sửa lại cách tính file_ratio
    full_size = len(pe.__data__)  # Kích thước toàn bộ file
    file_ratio = (size / full_size) * 100 if full_size else 0
    file_ratio = round(file_ratio, 2)

    # e_lfanew offset
    e_lfanew = pe.DOS_HEADER.e_lfanew

    return [
        ("dos-header > sha256", sha256_hash),
        ("size", f"0x{size:X} ({size} bytes)"),
        ("dos-header > location", location),
        ("entropy", str(entropy)),
        ("file > ratio", f"{file_ratio} %"),
        ("exe-header > offset", f"0x{e_lfanew:08X} (e_lfanew)"),
    ]

# Hàm parse chính
def parse_pe(file_path):
    data = {
        'DOS Header': [],
        'COFF File Header': [],
        'Optional Header': [],
        'Sections Table': [],
        'Import Table': [],
        'Export Table': [],
        'Resource Table': [],
        'Relocation Table': [],
    }

    try:
        pe = pefile.PE(file_path)

        # DOS HEADER
        data['DOS Header'] = parse_dos_header(pe)  # Thêm việc gọi hàm phân tích DOS Header



        # SECTIONS TABLE
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').rstrip('\x00')
            data['Sections Table'].append((
                hex(section.VirtualAddress),
                hex(section.Misc_VirtualSize),
                name
            ))

        # IMPORT TABLE (New format like PeStudio)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                    ordinal = imp.ordinal if imp.ordinal else '-'
                    data['Import Table'].append((
                        func_name,
                        dll_name,
                        "implicit",
                        str(ordinal)
                    ))
        else:
            data['Import Table'].append(('No imports found.', '-', '-', '-'))

        # EXPORT TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                func_name = exp.name.decode('utf-8', errors='ignore') if exp.name else 'None'
                data['Export Table'].append((
                    hex(exp.address) if isinstance(exp.address, int) else str(exp.address),
                    '',
                    func_name
                ))
        else:
            data['Export Table'].append(('N/A', 'N/A', 'No exports found.'))

        # RESOURCE TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                name = str(resource_type.name) if resource_type.name else str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id, 'Unknown'))
                data['Resource Table'].append((
                    hex(resource_type.struct.OffsetToData),
                    '',
                    name
                ))
        else:
            data['Resource Table'].append(('N/A', 'N/A', 'No resources found.'))

        # RELOCATION TABLE
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                for reloc in base_reloc.entries:
                    data['Relocation Table'].append((
                        hex(reloc.rva),
                        '',
                        f"Type: {reloc.type}"
                    ))
        else:
            data['Relocation Table'].append(('N/A', 'N/A', 'No relocation entries.'))

    except Exception as e:
        print(f"Error parsing PE file: {e}")

    return data
