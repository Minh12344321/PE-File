# pe_parser.py
import pefile

def parse_dump(dump_data):
    parsed = []
    for line in dump_data:
        parts = line.strip().split(None, 2)  # Tách thành 3 phần: Address, Value, Meaning
        if len(parts) == 3:
            addr, val, name = parts
            parsed.append((addr, val, name))
    return parsed

def parse_pe(file_path):
    pe = pefile.PE(file_path)

    data = {
        'DOS Header': [],
        'COFF File Header': [],
        'Optional Header': [],
        'Sections Table': [],
        'Import Table': [],
    }

    # DOS HEADER
    data['DOS Header'] = parse_dump(pe.DOS_HEADER.dump())

    # COFF FILE HEADER
    data['COFF File Header'] = parse_dump(pe.FILE_HEADER.dump())

    # OPTIONAL HEADER
    data['Optional Header'] = parse_dump(pe.OPTIONAL_HEADER.dump())

    # SECTIONS TABLE
    for section in pe.sections:
        data['Sections Table'].append((
            hex(section.VirtualAddress),
            section.Name.decode(errors='ignore').rstrip('\x00'),
            f"Size: {hex(section.Misc_VirtualSize)}"
        ))

    # IMPORT TABLE
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            data['Import Table'].append((hex(entry.struct.FirstThunk), '', dll_name))
    else:
        data['Import Table'].append(('N/A', 'N/A', 'No imports found.'))

    return data
