#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_NAME_SIZE 255

#define COFF_HEADER_MAGIC 0x4550
#define DOS_HEADER_MAGIC  0x5a4d

#define CERTIFICATE_VERSION 0x200
#define CERTIFICATE_TYPE 0x2

#define PE_OPTIONAL_HEADER_SIGNATURE_32 0x010b
#define PE_OPTIONAL_HEADER_SIGNATURE_64 0x020b

enum IMAGE_DIRECTORY_ENTRY {
    IMAGE_DIRECTORY_ENTRY_EXPORT         = 0,
    IMAGE_DIRECTORY_ENTRY_IMPORT         = 1,
    IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3,
    IMAGE_DIRECTORY_ENTRY_SECURITY       = 4,
    IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5,
    IMAGE_DIRECTORY_ENTRY_DEBUG          = 6,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8,
    IMAGE_DIRECTORY_ENTRY_TLS            = 9,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11,
    IMAGE_DIRECTORY_ENTRY_IAT            = 12,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    IMAGE_DIRECTORY_ENTRY_UNUSED         = 15,
    IMAGE_DIRECTORY_ENTRY_NB_ARGS
};

typedef struct _dos_header {
    uint16_t magic;
    uint16_t last_size;
    uint16_t block_count;
    uint16_t reloc_count;
    uint16_t header_size;
    uint16_t min_alloc;
    uint16_t max_alloc;
    uint16_t reg_ss;
    uint16_t reg_sp;
    uint16_t checksum;
    uint16_t reg_ip;
    uint16_t reg_cs;
    uint16_t reloc_pos;
    uint16_t overlay_number;
    uint16_t reserved[4];
    uint16_t oem_id;
    uint16_t oem_info;
    uint16_t reserved2[10];
    uint16_t lfa_new;
} DOS_Header;

typedef struct _coff_header {
    uint32_t magic;
    uint16_t arch;
    uint16_t section_count;
    uint32_t timestamp;
    uint32_t symbol_table_pointer;
    uint32_t symbol_count;
    uint16_t optional_header_size;
    uint16_t characteristics;
} COFF_Header;

typedef struct _data_directory {
    uint32_t address;
    uint32_t size;
} Data_Directory;

typedef struct _pe_optional_header {
    uint16_t signature;
    uint8_t linker_major;
    uint8_t linker_minor;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point_address;
    uint32_t base_code;
    uint64_t base_image;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t os_major;
    uint16_t os_minor;
    uint16_t image_major;
    uint16_t image_minor;
    uint16_t subsystem_major;
    uint16_t subsystem_minor;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t header_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserved_size;    // On a 32-bit PE this should be a uint32_t but the code will handle it
    uint64_t stack_commit_size;      // On a 32-bit PE this should be a uint32_t but the code will handle it
    uint64_t heap_reserve_size;      // On a 32-bit PE this should be a uint32_t but the code will handle it
    uint64_t heap_commit_size;       // On a 32-bit PE this should be a uint32_t but the code will handle it
    uint32_t loader_flags;
    uint32_t rva_number_size;
    Data_Directory* data_directory;
} PE_Optional_Header;

typedef struct _section_header {
    char name[8];

    union {
        uint32_t physical_address;
        uint32_t virtual_size;
    } compiler_dependant;

    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_pointer;
    uint32_t relocations_pointer;
    uint32_t line_number_pointer;
    uint16_t relocation_count;
    uint16_t line_number_count;
    uint32_t characteristics;
} Section_Header;

typedef struct _image_import_descriptor {
    union {
        uint32_t characteristics;
        uint32_t original_first_thunk;
    } something;

    uint32_t timestamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} Image_Import_Descriptor;

typedef struct _image_export_directory {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t name;
    uint32_t base;
    uint32_t function_count;
    uint32_t name_count;
    uint32_t function_pointer;
    uint32_t name_pointer;
    uint32_t name_ordinals_pointer;
} Image_Export_Directory;

typedef struct _megastructure_information {
    Image_Export_Directory image_export;
    Data_Directory directory_addresses[16];
    Section_Header* section_headers;
    Image_Import_Descriptor* image_imports;
    uint32_t** image_lookup_descriptors;
    uint32_t* export_module_function_pointers;
    uint8_t* signature;
    char*** import_function_names;
    char** export_module_functions;
    char** import_dll_names;
    char* export_module_name;
    uint32_t signature_length;
    uint16_t image_import_count;
    uint16_t section_count;
    bool bits_64;
} Megastructure_Information;



bool is_seek_forward(uint32_t seek_addr);
uint32_t find_offset_from_rva(int section_count, Section_Header* section_headers, uint32_t rva);

bool read_dos_header(FILE* pe_file, DOS_Header* dos_header);
bool read_coff_header(FILE* pe_file, COFF_Header* coff_header);
bool read_certificate(FILE* pe_file, Megastructure_Information* megastructure_information);
bool read_single_name(FILE* pe_file, size_t seek_pos, char** name_addr);
bool read_export_directory(FILE* pe_file, Megastructure_Information* megastructure_information);

static inline bool read_import_dll_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index)
{
    return read_single_name(pe_file, megastructure_information->image_imports[import_index].name, &(megastructure_information->import_dll_names[import_index]));
}

static inline bool read_import_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index, uint32_t function_name)
{
    return read_single_name(pe_file, megastructure_information->image_lookup_descriptors[import_index][function_name] + 2, &(megastructure_information->import_function_names[import_index][function_name]));
}

static inline bool read_export_module_name(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    return read_single_name(pe_file, megastructure_information->image_export.name, &(megastructure_information->export_module_name));
}

static inline bool read_export_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t name_index)
{
    return read_single_name(pe_file, megastructure_information->export_module_function_pointers[name_index], &(megastructure_information->export_module_functions[name_index]));
}