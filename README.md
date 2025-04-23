# PE (Portable Executable) Format

## I. Khái niệm PE (Portable Executable)

- **PE file** là định dạng file được Windows sử dụng cho các file thực thi như `.exe`, `.dll`, `.sys`, ...
- **PE header** chứa tất cả thông tin cần thiết để hệ điều hành nạp chương trình vào bộ nhớ và thực thi nó.

### Thành phần PE Header

| Thành phần               | Mô tả                                                                                           |
|--------------------------|------------------------------------------------------------------------------------------------|
| **1. MS-DOS Header**      | Phần header của chương trình DOS cũ (chủ yếu để tương thích)                                    |
| **2. MS-DOS Stub**        | Một đoạn code in thông báo kiểu: "This program cannot be run in DOS mode."                    |
| **3. PE Signature**       | Dấu hiệu nhận diện file PE (4 bytes: `0x50 0x45 0x00 0x00`)                                  |
| **4. PE File Header**     | Thông tin cơ bản về file (số lượng sections, thời gian tạo, flags)                            |
| **5. Optional Header**    | Thông tin cần thiết để loader thực thi chương trình (entry point, base address, size...)      |
| **6. Section Table**      | Mô tả các section (mã lệnh, dữ liệu, tài nguyên)                                              |
| **7. Sections**           | Thực tế dữ liệu (mã máy, dữ liệu, tài nguyên...)                                               |

---

## II. Các thành phần chi tiết

### 1. MS-DOS Header (64 bytes)

- **Chứa**:
  - Magic number **MZ** (`0x4D5A`) – nhận diện file DOS.
  - **e_lfanew** (offset `0x3C`): offset trỏ tới PE Header.

```cpp
typedef struct _IMAGE_DOS_HEADER { 
    WORD e_magic;      // MZ = 0x5A4D
    WORD e_cblp;       // Bytes on last page
    ...
    LONG e_lfanew;     // Offset to PE header
} IMAGE_DOS_HEADER;

2. PE Signature

    Giá trị cố định: "PE\0\0" (50 45 00 00h).

3. COFF File Header (PE File Header)

Thông tin về file thực thi:

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;              // Kiến trúc CPU (0x14C cho x86)
    WORD  NumberOfSections;     // Số lượng section
    DWORD TimeDateStamp;        // Thời gian tạo
    DWORD PointerToSymbolTable; // Không dùng trong file PE
    DWORD NumberOfSymbols;      // Không dùng trong file PE
    WORD  SizeOfOptionalHeader; // Kích thước của Optional Header
    WORD  Characteristics;      // Các flag (file thực thi, DLL, 32-bit,…)
} IMAGE_FILE_HEADER;

Trường	Vai trò
Machine	Xác định CPU (ví dụ: 0x14C = Intel 386)
NumberOfSections	Số lượng section
TimeDateStamp	Thời gian file được tạo
Characteristics	Cờ xác định loại file (executable, DLL, 32-bit,...)
4. Optional Header

(Rất quan trọng đối với loader.)

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;                  // 0x10B cho PE32
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD AddressOfEntryPoint;    // Entry Point (điểm bắt đầu thực thi)
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;              // Địa chỉ load mặc định
    DWORD SectionAlignment;       // Canh chỉnh section trong bộ nhớ
    DWORD FileAlignment;          // Canh chỉnh section trong file
    ...
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // Bảng các thành phần như Import, Export Table
} IMAGE_OPTIONAL_HEADER32;

Trường	Vai trò
Magic	0x10B (PE32) hoặc 0x20B (PE32+)
AddressOfEntryPoint	Địa chỉ hàm chính khi bắt đầu thực thi
ImageBase	Địa chỉ cơ sở trong bộ nhớ (mặc định 0x400000 cho exe)
SectionAlignment	Đơn vị căn chỉnh khi nạp vào RAM
FileAlignment	Đơn vị căn chỉnh khi lưu file
DataDirectory	Chứa địa chỉ Import table, Export table, Resource table
5. Section Table (Section Headers)

Mỗi section chứa thông tin như .text (code), .data (dữ liệu), .rdata (read-only data), .rsrc (resource).

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];                   // Tên section (.text, .data,...)
    DWORD VirtualSize;              // Kích thước khi load vào bộ nhớ
    DWORD VirtualAddress;           // Địa chỉ ảo tương đối
    DWORD SizeOfRawData;            // Kích thước trong file
    DWORD PointerToRawData;         // Offset trong file
    DWORD Characteristics;          // Quyền truy cập: đọc/ghi/thực thi
} IMAGE_SECTION_HEADER;

Ví dụ Section	Vai trò
.text	Chứa mã lệnh (code)
.data	Chứa dữ liệu có thể thay đổi
.rdata	Dữ liệu chỉ đọc
.rsrc	Tài nguyên (icon, ảnh, âm thanh)
IV. Cách Windows Loader nạp chương trình

Khi một file PE được nạp:

    Đọc MS-DOS Header → tìm PE Header thông qua e_lfanew.

    Xác nhận PE Signature ("PE\0\0").

    Đọc COFF File Header:

        Biết được số lượng sections.

    Đọc Optional Header:

        ImageBase → nơi chương trình muốn được nạp.

        AddressOfEntryPoint → nơi thực thi đầu tiên.

        SectionAlignment, FileAlignment → căn chỉnh bộ nhớ.

        Data Directory → tìm Import Table (các DLL cần load trước).

    Nạp các Sections:

        Tạo vùng bộ nhớ ảo tương ứng ImageBase.

        Nạp từng section vào đúng địa chỉ ảo.

    Xử lý Relocation nếu cần:

        Nếu ImageBase bị trùng, phải chỉnh sửa địa chỉ.

    Load các thư viện DLL được chỉ định trong Import Table.

    Nhảy đến EntryPoint và bắt đầu thực thi chương trình.

V. Các thành phần quan trọng cần lưu ý

    e_lfanew: Offset tới PE header.

    PE Signature: Xác nhận đây là file PE.

    NumberOfSections: Biết file có bao nhiêu section.

    ImageBase: Địa chỉ file mong muốn trong bộ nhớ.

    AddressOfEntryPoint: Địa chỉ bắt đầu thực thi.

    DataDirectory: Thông tin Import/Export/Resource/Relocation Table.

    .text, .data, .rdata, .rsrc: Các vùng dữ liệu chính.

    Relocation Table: Khi ImageBase bị thay đổi phải sửa địa chỉ.

    Import Table: Liệt kê DLLs và APIs cần thiết.
