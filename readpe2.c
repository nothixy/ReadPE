#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

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

bool is_seek_forward(uint32_t seek_addr)
{
    static uint32_t max_seek_addr = 0;
    if (seek_addr < max_seek_addr)
    {
        return false;
    }
    max_seek_addr = seek_addr;

    return true;
}

bool read_dos_header(FILE* pe_file, DOS_Header* dos_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(dos_header, sizeof(DOS_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return dos_header->magic == DOS_HEADER_MAGIC;
}

bool read_coff_header(FILE* pe_file, COFF_Header* coff_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(coff_header, sizeof(COFF_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return coff_header->magic == COFF_HEADER_MAGIC;
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

bool read_certificate(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[4].address, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    uint16_t version;
    uint16_t type;
    if(fread(&(megastructure_information->signature_length), sizeof(uint32_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if(fread(&version, sizeof(uint16_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if(fread(&type, sizeof(uint16_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if (version != CERTIFICATE_VERSION)
    {
        megastructure_information->signature_length = 0;
        return true;  // no signature
    }
    if (type != CERTIFICATE_TYPE)
    {
        megastructure_information->signature_length = 0;
        return true;  // no signature
    }
    if (megastructure_information->signature_length < 8)
    {
        return false;  // file corrupted
    }

    megastructure_information->signature_length -= 8;
    megastructure_information->signature = malloc(megastructure_information->signature_length * sizeof(uint8_t));
    return fread(megastructure_information->signature, megastructure_information->signature_length * sizeof(uint8_t), 1, pe_file) == 1;
}

static inline bool is_last_image_import_descriptor(Image_Import_Descriptor* descriptor)
{
    return descriptor->first_thunk == 0 && descriptor->forwarder_chain == 0 && descriptor->name == 0 && descriptor->something.original_first_thunk == 0 && descriptor->timestamp == 0;
}

bool read_import_table(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[1].address, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    megastructure_information->image_imports = malloc(0);
    while (true)
    {
        megastructure_information->image_imports = realloc(megastructure_information->image_imports, (megastructure_information->image_import_count + 1) * sizeof(Image_Import_Descriptor));
        if(fread(&megastructure_information->image_imports[megastructure_information->image_import_count], sizeof(Image_Import_Descriptor), 1, pe_file) <= 0)
        {
            return false;
        }
        megastructure_information->image_imports[megastructure_information->image_import_count].name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_imports[megastructure_information->image_import_count].name);
        megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk);
        if (is_last_image_import_descriptor(&(megastructure_information->image_imports[megastructure_information->image_import_count])))
        {
            megastructure_information->image_imports = realloc(megastructure_information->image_imports, megastructure_information->image_import_count * sizeof(Image_Import_Descriptor));
            break;
        }
        megastructure_information->image_import_count++;
    }
    if (megastructure_information->image_import_count != 0)
    {
        megastructure_information->import_dll_names = calloc(megastructure_information->image_import_count, sizeof(char*));
        megastructure_information->import_function_names = calloc(megastructure_information->image_import_count, sizeof(char**));
        megastructure_information->image_lookup_descriptors = calloc(megastructure_information->image_import_count, sizeof(uint32_t*));
    }
    return true;
}

static bool read_single_name(FILE* pe_file, size_t seek_pos, char** name_addr)
{
    fseek(pe_file, seek_pos, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    int character_count = 0;
    *name_addr = malloc(NAME_MAX+1);
    int c;
    do
    {
        if((c = fgetc(pe_file)) == EOF)
        {
            return false;
        }
        (*name_addr)[character_count] = (char)c;
        character_count++;
    }
    while (c != 0 && character_count < NAME_MAX);

    (*name_addr)[character_count] = '\0';

    return true;
}

static inline bool read_import_dll_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index)
{
    return read_single_name(pe_file, megastructure_information->image_imports[import_index].name, &(megastructure_information->import_dll_names[import_index]));
}

bool read_import_lookup_descriptors(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index)
{
    fseek(pe_file, megastructure_information->image_imports[import_index].something.original_first_thunk, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    int count = 0;
    megastructure_information->image_lookup_descriptors[import_index] = malloc(0);
    uint64_t lookup_descriptor64;
    uint32_t lookup_descriptor32;
    while (true)
    {
        if (megastructure_information->bits_64)
        {
            if(fread(&lookup_descriptor64, sizeof(uint64_t), 1, pe_file) <= 0)
            {
                return false;
            }
            if ((lookup_descriptor64 >> 63) == 1)
            {
                continue;
            }
        }
        else
        {
            if(fread(&lookup_descriptor32, sizeof(uint32_t), 1, pe_file) <= 0)
            {
                return false;
            }
            if ((lookup_descriptor32 >> 31) == 1)
            {
                continue;
            }
        }
        megastructure_information->image_lookup_descriptors[import_index] = realloc(megastructure_information->image_lookup_descriptors[import_index], (count + 1) * sizeof(uint32_t));
        uint32_t rva = lookup_descriptor64 & ((uint32_t) (1 << 31) - 1);
        if (rva == 0 && (!megastructure_information->bits_64 || (uint32_t) (lookup_descriptor64 >> 31) == 0))
        {
            megastructure_information->image_lookup_descriptors[import_index][count] = (uint32_t)(-1);
            megastructure_information->import_function_names[import_index] = calloc(count+1, sizeof(char*));

            return true;
        }

        megastructure_information->image_lookup_descriptors[import_index][count] = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, rva);
        count++;
    }
}

static inline bool read_import_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t import_index, uint32_t function_name)
{
    return read_single_name(pe_file, megastructure_information->image_lookup_descriptors[import_index][function_name] + 2, &(megastructure_information->import_function_names[import_index][function_name]));
}

void read_export_directory(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[0].address, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    fread(&(megastructure_information->image_export), sizeof(Image_Export_Directory), 1, pe_file);
    megastructure_information->image_export.name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name);
    megastructure_information->image_export.name_pointer = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name_pointer);
    if (megastructure_information->image_export.name_count != 0)
    {
        megastructure_information->export_module_functions = calloc(megastructure_information->image_export.name_count, sizeof(char*));
        megastructure_information->export_module_function_pointers = calloc(megastructure_information->image_export.name_count, sizeof(uint32_t));
    }
}

static inline bool read_export_module_name(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    return read_single_name(pe_file, megastructure_information->image_export.name, &(megastructure_information->export_module_name));
}

void read_export_function_name_pointers(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->image_export.name, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    fread(megastructure_information->export_module_function_pointers, sizeof(uint32_t), megastructure_information->image_export.name_count, pe_file);
    for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
    {
        megastructure_information->export_module_function_pointers[i] = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->export_module_function_pointers[i]);
    }
}

static inline bool read_export_function_name(FILE* pe_file, Megastructure_Information* megastructure_information, uint32_t name_index)
{
    return read_single_name(pe_file, megastructure_information->export_module_function_pointers[name_index], &(megastructure_information->export_module_functions[name_index]));
}

void read_next_data(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    while (true)
    {
        uint64_t min_address = (uint64_t) -1;
        for (int i = 0; i < IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
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
        for (int i = 0; i < IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
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
    Megastructure_Information megastructure_information = {0};
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
    assert(is_seek_forward(ftell(pe_file)));
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
    if (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_64)
    {
        fread(&(pe_optional_header.stack_reserved_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.stack_commit_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.heap_reserve_size), sizeof(uint64_t), 1, pe_file);
        fread(&(pe_optional_header.heap_commit_size), sizeof(uint64_t), 1, pe_file);
    }
    else if (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_32)
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
    fread(megastructure_information.directory_addresses, sizeof(Data_Directory), IMAGE_DIRECTORY_ENTRY_NB_ARGS, pe_file);

    if (pe_optional_header.rva_number_size > IMAGE_DIRECTORY_ENTRY_NB_ARGS)
    {
        fseek(pe_file, (pe_optional_header.rva_number_size - IMAGE_DIRECTORY_ENTRY_NB_ARGS) * sizeof(Data_Directory), SEEK_CUR);
        assert(is_seek_forward(ftell(pe_file)));
    }

    megastructure_information.section_headers = malloc(coff_header.section_count * sizeof(Section_Header));
    if (megastructure_information.section_headers == NULL)
    {
        fputs("An error has occurred\n", stderr);
        goto FINISH;
    }
    fread(megastructure_information.section_headers, sizeof(Section_Header), coff_header.section_count, pe_file);

    megastructure_information.section_count = coff_header.section_count;

    for (int i = 0; i < IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
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

    megastructure_information.bits_64 = (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_64);

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
        return 1;
    }
    read_pe(argv[1]);

    return 0;
}
