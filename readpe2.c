#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define IMAGE_DIRECTORY_ENTRY_EXPORT                0
#define IMAGE_DIRECTORY_ENTRY_IMPORT                1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE              2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION             3
#define IMAGE_DIRECTORY_ENTRY_SECURITY              4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC             5
#define IMAGE_DIRECTORY_ENTRY_DEBUG                 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE          7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR             8
#define IMAGE_DIRECTORY_ENTRY_TLS                   9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG           10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT          11
#define IMAGE_DIRECTORY_ENTRY_IAT                   12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT          13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR        14
#define IMAGE_DIRECTORY_ENTRY_UNUSED                15

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

void set_max_seek_address(uint32_t seek_addr)
{
    static uint32_t max_seek_addr = 0;
    if (seek_addr < max_seek_addr)
    {
        fprintf(stderr, "Seekd back\n");
        exit(0);
    }
    max_seek_addr = seek_addr;
}

bool read_dos_header(FILE* pe_file, DOS_Header* dos_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    fread(dos_header, sizeof(DOS_Header), 1, pe_file);
    if (dos_header->magic != 0x5a4d)
    {
        fprintf(stderr, "Not a DOS executable\n");
        return false;
    }
    return true;
}

bool read_coff_header(FILE* pe_file, COFF_Header* coff_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    fread(coff_header, sizeof(COFF_Header), 1, pe_file);
    if (coff_header->magic != 0x4550)
    {
        fprintf(stderr, "Not a COFF header\n");
        return false;
    }
    return true;
}

uint32_t find_offset_from_rva(int section_count, Section_Header* section_headers, uint32_t rva)
{
    for (int i = 0; i < section_count; i++)
    {
        if (section_headers[i].virtual_address <= rva && rva < section_headers[i].virtual_address + section_headers[i].compiler_dependant.virtual_size)
        {
            return rva - section_headers[i].virtual_address + section_headers[i].raw_data_pointer;
        }
    }
    return 0;
}

void read_certificate(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[4].address, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    uint16_t version;
    uint16_t type;
    fread(&(megastructure_information->signature_length), sizeof(uint32_t), 1, pe_file);
    fread(&version, sizeof(uint16_t), 1, pe_file);
    fread(&type, sizeof(uint16_t), 1, pe_file);
    if (version != 0x200)
    {
        megastructure_information->signature_length = 0;
        return;
    }
    if (type != 0x2)
    {
        megastructure_information->signature_length = 0;
        return;
    }
    if (megastructure_information->signature_length != 0)
    {
        megastructure_information->signature_length -= 8;
        megastructure_information->signature = malloc(megastructure_information->signature_length * sizeof(uint8_t));
        fread(megastructure_information->signature, sizeof(uint8_t), megastructure_information->signature_length, pe_file);
    }
}

void read_import_table(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[1].address, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    megastructure_information->image_imports = malloc(0);
    while (true)
    {
        megastructure_information->image_imports = realloc(megastructure_information->image_imports, (megastructure_information->image_import_count + 1) * sizeof(Image_Import_Descriptor));
        fread(&megastructure_information->image_imports[megastructure_information->image_import_count], sizeof(Image_Import_Descriptor), 1, pe_file);
        megastructure_information->image_imports[megastructure_information->image_import_count].name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_imports[megastructure_information->image_import_count].name);
        megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk);
        if (megastructure_information->image_imports[megastructure_information->image_import_count].first_thunk == 0 && megastructure_information->image_imports[megastructure_information->image_import_count].forwarder_chain == 0 && megastructure_information->image_imports[megastructure_information->image_import_count].name == 0 && megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk == 0 && megastructure_information->image_imports[megastructure_information->image_import_count].timestamp == 0)
        {
            megastructure_information->image_imports = realloc(megastructure_information->image_imports, megastructure_information->image_import_count * sizeof(Image_Import_Descriptor));
            break;
        }
        megastructure_information->image_import_count++;
    }
    if (megastructure_information->image_import_count != 0)
    {
        megastructure_information->import_dll_names = malloc(megastructure_information->image_import_count * sizeof(char*));
        megastructure_information->import_function_names = malloc(megastructure_information->image_import_count * sizeof(char**));
        megastructure_information->image_lookup_descriptors = malloc(megastructure_information->image_import_count * sizeof(uint32_t*));
        memset(megastructure_information->import_dll_names, 0, megastructure_information->image_import_count * sizeof(char*));
        memset(megastructure_information->import_function_names, 0, megastructure_information->image_import_count * sizeof(char**));
        memset(megastructure_information->image_lookup_descriptors, 0, megastructure_information->image_import_count * sizeof(uint32_t*));
    }
}

void read_import_dll_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index)
{
    fseek(pe_file, megastructure_information->image_imports[import_index].name, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    int character_count = 0;
    megastructure_information->import_dll_names[import_index] = malloc(0);
    char c;
    do
    {
        megastructure_information->import_dll_names[import_index] = realloc(megastructure_information->import_dll_names[import_index], (character_count + 1) * sizeof(char));
        fread(&c, sizeof(char), 1, pe_file);
        megastructure_information->import_dll_names[import_index][character_count] = c;
        character_count++;
    }
    while (c != 0);
}

void read_import_lookup_descriptors(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index)
{
    fseek(pe_file, megastructure_information->image_imports[import_index].something.original_first_thunk, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    int count = 0;
    megastructure_information->image_lookup_descriptors[import_index] = malloc(0);
    uint64_t lookup_descriptor64;
    uint32_t lookup_descriptor32;
    while (true)
    {
        if (megastructure_information->bits_64)
        {
            megastructure_information->image_lookup_descriptors[import_index] = realloc(megastructure_information->image_lookup_descriptors[import_index], (count + 1) * sizeof(uint32_t));
            fread(&lookup_descriptor64, sizeof(uint64_t), 1, pe_file);
            if ((lookup_descriptor64 >> 63) == 1)
            {
                continue;
            }
            megastructure_information->image_lookup_descriptors[import_index][count] = lookup_descriptor64 & ((uint32_t) (1 << 31) - 1);
            if (megastructure_information->image_lookup_descriptors[import_index][count] == 0 && (uint32_t) (lookup_descriptor64 >> 31) == 0)
            {
                megastructure_information->image_lookup_descriptors[import_index][count] = (uint32_t) -1;
                count++;
                break;
            }
        }
        else
        {
            megastructure_information->image_lookup_descriptors[import_index] = realloc(megastructure_information->image_lookup_descriptors[import_index], (count + 1) * sizeof(uint32_t));
            fread(&lookup_descriptor32, sizeof(uint32_t), 1, pe_file);
            if ((lookup_descriptor32 >> 31) == 1)
            {
                continue;
            }
            megastructure_information->image_lookup_descriptors[import_index][count] = lookup_descriptor32 & ((uint32_t) (1 << 31) - 1);
            if (megastructure_information->image_lookup_descriptors[import_index][count] == 0)
            {
                megastructure_information->image_lookup_descriptors[import_index][count] = (uint32_t) -1;
                count++;
                break;
            }
        }
        megastructure_information->image_lookup_descriptors[import_index][count] = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_lookup_descriptors[import_index][count]);
        count++;
    }
    if (count != 0)
    {
        megastructure_information->import_function_names[import_index] = malloc(count * sizeof(char*));
        memset(megastructure_information->import_function_names[import_index], 0, count * sizeof(char*));
    }
}

void read_import_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index, uint32_t function_name)
{
    fseek(pe_file, megastructure_information->image_lookup_descriptors[import_index][function_name] + 2, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    int count = 0;
    char c;
    megastructure_information->import_function_names[import_index][function_name] = malloc(0);
    do
    {
        megastructure_information->import_function_names[import_index][function_name] = realloc(megastructure_information->import_function_names[import_index][function_name], (count + 1) * sizeof(char));
        fread(&c, sizeof(char), 1, pe_file);
        megastructure_information->import_function_names[import_index][function_name][count] = c;
        count++;
    }
    while (c != 0);
}

void read_export_directory(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[0].address, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    fread(&(megastructure_information->image_export), sizeof(Image_Export_Directory), 1, pe_file);
    megastructure_information->image_export.name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name);
    megastructure_information->image_export.name_pointer = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name_pointer);
    if (megastructure_information->image_export.name_count != 0)
    {
        megastructure_information->export_module_functions = malloc(megastructure_information->image_export.name_count * sizeof(char*));
        megastructure_information->export_module_function_pointers = malloc(megastructure_information->image_export.name_count * sizeof(uint32_t));
        memset(megastructure_information->export_module_functions, 0, megastructure_information->image_export.name_count * sizeof(char*));
        memset(megastructure_information->export_module_function_pointers, 0, megastructure_information->image_export.name_count * sizeof(uint32_t));
    }
}

void read_export_module_name(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->image_export.name, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    megastructure_information->export_module_name = malloc(0);
    char c;
    int count = 0;
    do
    {
        megastructure_information->export_module_name = realloc(megastructure_information->export_module_name, (count + 1) * sizeof(char));
        fread(&c, sizeof(char), 1, pe_file);
        megastructure_information->export_module_name[count] = c;
        count++;
    }
    while (c != 0);
}

void read_export_function_name_pointers(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->image_export.name, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    fread(megastructure_information->export_module_function_pointers, sizeof(uint32_t), megastructure_information->image_export.name_count, pe_file);
    for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
    {
        megastructure_information->export_module_function_pointers[i] = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->export_module_function_pointers[i]);
    }
}

void read_export_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t name_index)
{
    fseek(pe_file, megastructure_information->export_module_function_pointers[name_index], SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    char c;
    int count = 0;
    megastructure_information->export_module_functions[name_index] = malloc(0);
    do
    {
        megastructure_information->export_module_functions[name_index] = realloc(megastructure_information->export_module_functions[name_index], (count + 1) * sizeof(char));
        fread(&c, sizeof(char), 1, pe_file);
        megastructure_information->export_module_functions[name_index][count] = c;
        count++;
    }
    while (c != 0);
}

void read_next_data(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    while (true)
    {
        uint64_t min_address = (uint64_t) -1;
        for (int i = 0; i < 16; i++)
        {
            if (megastructure_information->directory_addresses[i].address != 0 && megastructure_information->directory_addresses[i].address < min_address)
            {
                min_address = megastructure_information->directory_addresses[i].address;
            }
        }
        if (megastructure_information->image_imports != NULL)
        {
            for (int i = 0; i < megastructure_information->image_import_count; i++)
            {
                if (megastructure_information->image_imports[i].something.original_first_thunk != 0 && megastructure_information->image_imports[i].something.original_first_thunk < min_address)
                {
                    min_address = megastructure_information->image_imports[i].something.original_first_thunk;
                }
                if (megastructure_information->image_imports[i].name != 0 && megastructure_information->image_imports[i].name < min_address)
                {
                    min_address = megastructure_information->image_imports[i].name;
                }
                if (megastructure_information->image_lookup_descriptors[i] != NULL)
                {
                    for (uint32_t j = 0; megastructure_information->image_lookup_descriptors[i][j] != (uint32_t) -1; j++)
                    {
                        if (megastructure_information->image_lookup_descriptors[i][j] != 0 && megastructure_information->image_lookup_descriptors[i][j] < min_address)
                        {
                            min_address = megastructure_information->image_lookup_descriptors[i][j];
                        }
                    }
                }
            }
        }
        if (megastructure_information->image_export.name != 0 && megastructure_information->image_export.name < min_address)
        {
            min_address = megastructure_information->image_export.name;
        }
        if (megastructure_information->image_export.name_pointer != 0 && megastructure_information->image_export.name_pointer < min_address)
        {
            min_address = megastructure_information->image_export.name_pointer;
        }
        if (megastructure_information->export_module_function_pointers != NULL)
        {
            for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
            {
                if (megastructure_information->export_module_function_pointers[i] != 0 && megastructure_information->export_module_function_pointers[i] < min_address)
                {
                    megastructure_information->export_module_function_pointers[i] = min_address;
                }
            }
        }
        if (min_address == (uint64_t) -1)
        {
            break;
        }
        for (int i = 0; i < 16; i++)
        {
            if (megastructure_information->directory_addresses[i].address == min_address)
            {
                switch (i)
                {
                    case 0:
                        read_export_directory(pe_file, megastructure_information);
                        megastructure_information->directory_addresses[i].address = 0;
                        break;
                    case 1:
                        read_import_table(pe_file, megastructure_information);
                        megastructure_information->directory_addresses[i].address = 0;
                        break;
                    case 4:
                        read_certificate(pe_file, megastructure_information);
                        megastructure_information->directory_addresses[i].address = 0;
                        break;
                    default:
                        break;
                }
                goto NEXT_ITERATION;
            }
        }
        if (megastructure_information->image_imports != NULL)
        {
            for (uint16_t i = 0; i < megastructure_information->image_import_count; i++)
            {
                if (megastructure_information->image_imports[i].something.original_first_thunk == min_address)
                {
                    read_import_lookup_descriptors(pe_file, megastructure_information, i);
                    megastructure_information->image_imports[i].something.original_first_thunk = 0;
                    goto NEXT_ITERATION;
                }
                if (megastructure_information->image_imports[i].name == min_address)
                {
                    read_import_dll_name(pe_file, megastructure_information, i);
                    megastructure_information->image_imports[i].name = 0;
                    goto NEXT_ITERATION;
                }
                if (megastructure_information->image_lookup_descriptors[i] != NULL)
                {
                    for (uint32_t j = 0; megastructure_information->image_lookup_descriptors[i][j] != (uint32_t) -1; j++)
                    {
                        if (megastructure_information->image_lookup_descriptors[i][j] == min_address)
                        {
                            read_import_function_name(pe_file, megastructure_information, i, j);
                            megastructure_information->image_lookup_descriptors[i][j] = 0;
                            goto NEXT_ITERATION;
                        }
                    }
                }
            }
        }
        if (megastructure_information->image_export.name == min_address)
        {
            read_export_module_name(pe_file, megastructure_information);
            megastructure_information->image_export.name = 0;
            goto NEXT_ITERATION;
        }
        if (megastructure_information->image_export.name_pointer == min_address)
        {
            read_export_function_name_pointers(pe_file, megastructure_information);
            megastructure_information->image_export.name_pointer = 0;
            goto NEXT_ITERATION;
        }
        if (megastructure_information->export_module_function_pointers != NULL)
        {
            for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
            {
                if (megastructure_information->export_module_function_pointers[i] == min_address)
                {
                    read_export_function_name(pe_file, megastructure_information, i);
                    megastructure_information->export_module_function_pointers[i] = 0;
                    goto NEXT_ITERATION;
                }
            }
        }
NEXT_ITERATION:
    }
}

void read_pe(const char* filename)
{
    Megastructure_Information megastructure_information;
    memset(&megastructure_information, 0, sizeof(Megastructure_Information));
    PE_Optional_Header pe_optional_header;
    pe_optional_header.data_directory = NULL;
    COFF_Header coff_header;
    DOS_Header dos_header;
    FILE* pe_file = fopen(filename, "r");
    if (pe_file == NULL)
    {
        fputs("Error: can't open file\n", stderr);
        goto FINISH;
    }
    if (!read_dos_header(pe_file, &dos_header))
    {
        fputs("Error: invalid DOS header\n", stderr);
        goto FINISH;
    }
    fseek(pe_file, dos_header.lfa_new, SEEK_SET);
    set_max_seek_address(ftell(pe_file));
    if (!read_coff_header(pe_file, &coff_header))
    {
        fputs("Error: invalid COFF header\n", stderr);
        goto FINISH;
    }
    if (coff_header.optional_header_size == 0)
    {
        fputs("Error: this file doesn't have an optional header, I don't know how to proceed\n", stderr);
        goto FINISH;
    }
    fread(&pe_optional_header, offsetof(PE_Optional_Header, stack_reserved_size), 1, pe_file);
    if (pe_optional_header.signature == 0x020b)
    {
        fread(&(pe_optional_header.stack_reserved_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.stack_commit_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.heap_reserve_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.heap_commit_size), sizeof(uint64_t), 1, pe_file);
    }
    else if (pe_optional_header.signature == 0x010b)
    {
        fread(&(pe_optional_header.stack_reserved_size), sizeof(uint32_t), 1, pe_file);
        fread(&(pe_optional_header.stack_commit_size), sizeof(uint32_t), 1, pe_file);
        fread(&(pe_optional_header.heap_reserve_size), sizeof(uint32_t), 1, pe_file);
        fread(&(pe_optional_header.heap_commit_size), sizeof(uint32_t), 1, pe_file);
    }
    else
    {
        fputs("Error: this tool only supports PE executable files\n", stderr);
        goto FINISH;
    }
    fread(&(pe_optional_header.loader_flags), sizeof(uint32_t), 1, pe_file);
    fread(&(pe_optional_header.rva_number_size), sizeof(uint32_t), 1, pe_file);

    // There are 16 elements for PE files, however if this file is not a PE file, it can have more
    fread(megastructure_information.directory_addresses, sizeof(Data_Directory), 16, pe_file);

    if (pe_optional_header.rva_number_size > 16)
    {
        fseek(pe_file, (pe_optional_header.rva_number_size - 16) * sizeof(Data_Directory), SEEK_CUR);
        set_max_seek_address(ftell(pe_file));
    }

    megastructure_information.section_headers = malloc(coff_header.section_count * sizeof(Section_Header));
    if (megastructure_information.section_headers == NULL)
    {
        fputs("An error has occurred\n", stderr);
        goto FINISH;
    }
    fread(megastructure_information.section_headers, sizeof(Section_Header), coff_header.section_count, pe_file);

    megastructure_information.section_count = coff_header.section_count;

    for (int i = 0; i < 16; i++)
    {
        if (i != 4)
        {
            megastructure_information.directory_addresses[i].address = find_offset_from_rva(coff_header.section_count, megastructure_information.section_headers, megastructure_information.directory_addresses[i].address);
        }

        // Temporary because I can't parse other information
        if (i != 0 && i != 1 && i != 4)
        {
            megastructure_information.directory_addresses[i].address = 0;
        }
    }

    megastructure_information.bits_64 = (pe_optional_header.signature == 0x020b);

    read_next_data(pe_file, &megastructure_information);

    FILE* cert = fopen("certificate.der", "wb");
    if (cert != NULL)
    {
        fwrite(megastructure_information.signature, sizeof(uint8_t), megastructure_information.signature_length, cert);
        fclose(cert);
    }
    else
    {
        fputs("Can't write certificate file to certificate.der, ignoring\n", stderr);
    }

    for (uint32_t i = 0; i < megastructure_information.image_import_count; i++)
    {
        fprintf(stdout, "DLL = %s\n", megastructure_information.import_dll_names[i]);
        for (uint32_t j = 0; megastructure_information.image_lookup_descriptors[i][j] != (uint32_t) -1; j++)
        {
            fprintf(stdout, "Function = %s\n", megastructure_information.import_function_names[i][j]);
        }
    }

    if (megastructure_information.export_module_name != NULL)
    {
        fprintf(stdout, "Module name = %s\n", megastructure_information.export_module_name);

        for (uint32_t i = 0; i < megastructure_information.image_export.name_count; i++)
        {
            fprintf(stdout, "Function = %s\n", megastructure_information.export_module_functions[i]);
        }
    }

FINISH:
    free(megastructure_information.signature);
    free(megastructure_information.section_headers);
    if (megastructure_information.import_dll_names != NULL)
    {
        for (uint32_t i = 0; i < megastructure_information.image_import_count; i++)
        {
            free(megastructure_information.import_dll_names[i]);
        }
    }
    if (megastructure_information.import_function_names != NULL)
    {
        for (uint32_t i = 0; i < megastructure_information.image_import_count; i++)
        {
            for (uint32_t j = 0; megastructure_information.import_function_names[i][j] != NULL; j++)
            {
                free(megastructure_information.import_function_names[i][j]);
            }
            free(megastructure_information.import_function_names[i]);
        }
    }
    if (megastructure_information.image_lookup_descriptors != NULL)
    {
        for (uint32_t i = 0; i < megastructure_information.image_import_count; i++)
        {
            free(megastructure_information.image_lookup_descriptors[i]);
        }
    }
    if (megastructure_information.export_module_functions != NULL)
    {
        for (uint32_t i = 0; i < megastructure_information.image_export.function_count; i++)
        {
            free(megastructure_information.export_module_functions[i]);
        }
    }
    for (uint32_t i = 0; i < megastructure_information.image_export.name_count; i++)
    {
        free(megastructure_information.export_module_functions[i]);
    }
    free(megastructure_information.export_module_functions);
    free(megastructure_information.export_module_name);
    free(megastructure_information.image_imports);
    free(megastructure_information.import_dll_names);
    free(megastructure_information.import_function_names);
    free(megastructure_information.image_lookup_descriptors);
    fclose(pe_file);
    return;
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fputs("Invalid number of arguments\n", stderr);
    }
    read_pe(argv[1]);
}
