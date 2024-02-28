#ifndef READPE_H
#define READPE_H

#include <stdbool.h>
#include <stdint.h>

typedef struct _pe_dos_header {
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
} PE_DOS_Header;

typedef struct _pe_coff_header {
    uint32_t magic;
    uint16_t arch;
    uint16_t section_count;
    uint32_t timestamp;
    uint32_t symbol_table_pointer;
    uint32_t symbol_count;
    uint16_t optional_header_size;
    uint16_t characteristics;
} PE_COFF_Header;

typedef struct _pe_data_directory {
    uint32_t address;
    uint32_t size;
} PE_Data_Directory;

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
    PE_Data_Directory* data_directory;
} PE_Optional_Header;

typedef struct _pe_section_header {
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
} PE_Section_Header;

typedef struct _pe_image_import_descriptor {
    union {
        uint32_t characteristics;
        uint32_t original_first_thunk;
    } something;

    uint32_t timestamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} PE_Image_Import_Descriptor;

typedef struct _pe_image_export_directory {
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
} PE_Image_Export_Directory;

typedef struct _pe_resource_directory_table {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t named_entry_count;
    uint16_t id_entry_count;
} PE_Resource_Directory_Table;

typedef struct _pe_resource_directory_entry {
    uint32_t id_or_name_or_store_offset_type;
    uint32_t offset;
} PE_Resource_Directory_Entry;

typedef struct _pe_resource_data_entry {
    uint32_t data_rva;
    uint32_t size;
    uint32_t codepage;
    uint32_t reserved;
} PE_Resource_Data_Entry;

typedef struct _pe_information {
    PE_Image_Export_Directory image_export;
    PE_Data_Directory directory_addresses[16];
    PE_Section_Header* section_headers;
    PE_Image_Import_Descriptor* image_imports;
    uint8_t** resource_raw_data;
    PE_Resource_Data_Entry* resource_information;
    PE_Resource_Directory_Table* resource_tables;
    PE_Resource_Directory_Entry** resource_entries;
    uint32_t** image_lookup_descriptors;
    uint32_t* export_module_function_pointers;
    uint32_t* signature_length;
    uint8_t** signature;
    char*** import_function_names;
    char** export_module_functions;
    char** import_dll_names;
    uint32_t* import_function_allocated_per_dll;
    uint32_t* import_function_count_per_dll;
    char* export_module_name;
    uint32_t signature_count;
    uint32_t resource_count;
    uint32_t resource_table_count;
    uint32_t rsrc_base;
    uint16_t image_import_count;
    uint16_t section_count;
    bool bits_64;
} PE_Information;


typedef struct _pe_dll {
    const char* name;
    uint32_t _index;
} PE_DLL;

PE_Information* read_pe(const char* filename);
void free_megastructure(PE_Information** pps);

bool pe_get_dll(const PE_Information* pe_info, PE_DLL* dll, uint16_t dll_num);

#endif