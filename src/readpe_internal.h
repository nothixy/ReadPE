#ifndef READPE_INTERNAL_H
#define READPE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include "safe_alloc.h"
#include "readpe.h"

#define MAX_NAME_SIZE 255

#define COFF_HEADER_MAGIC 0x4550
#define DOS_HEADER_MAGIC  0x5a4d

#define CERTIFICATE_VERSION 0x200
#define CERTIFICATE_TYPE 0x2

#define PE_OPTIONAL_HEADER_SIGNATURE_32 0x010b
#define PE_OPTIONAL_HEADER_SIGNATURE_64 0x020b

#define READ_ERROR -1
#define READ_IGNORE -2

#define LOOKUP_DESCRIPTOR_END (uint32_t)(-1)


bool seek_forward(FILE* pe_file, uint32_t seek_addr);
uint32_t find_offset_from_rva(int section_count, PE_Section_Header* section_headers, uint32_t rva);
uint64_t get_min_addr(PE_Information* megastructure_information);

bool read_dos_header(FILE* pe_file, PE_DOS_Header* dos_header);
bool read_coff_header(FILE* pe_file, PE_COFF_Header* coff_header);
bool read_certificate(FILE* pe_file, PE_Information* megastructure_information);
bool read_single_name(FILE* pe_file, size_t seek_pos, char** name_addr);
bool read_export_directory(FILE* pe_file, PE_Information* megastructure_information);
int64_t read_lookup_descriptor(FILE* pe_file, PE_Information* megastructure_information);
bool read_resource_table_and_entries(FILE* pe_file, PE_Information* megastructure_information, uint32_t table_address);
bool read_resource_data_entry(FILE* pe_file, PE_Information* megastructure_information, uint32_t data_entry_address);
bool read_resource_by_index(FILE* pe_file, PE_Information* megastructure_information, uint32_t index);

static inline bool read_import_dll_name(FILE* pe_file, PE_Information* megastructure_information, uint32_t import_dll_index)
{
    uint32_t index = megastructure_information->dll_number++;
    return read_single_name(pe_file, megastructure_information->image_imports[import_dll_index].name, &(megastructure_information->import_dll[index].name));
}

static inline bool read_import_function_name(FILE* pe_file, PE_Information* megastructure_information, uint32_t import_dll_index, uint32_t function_lookup_index)
{
    uint32_t index = megastructure_information->import_dll[import_dll_index].function_number++;
    return read_single_name(pe_file, megastructure_information->image_lookup_descriptors[import_dll_index][function_lookup_index] + 2, &(megastructure_information->import_dll[import_dll_index].function_names[index]));
}

static inline bool read_export_module_name(FILE* pe_file, PE_Information* megastructure_information)
{
    return read_single_name(pe_file, megastructure_information->image_export.name, &(megastructure_information->export_module_name));
}

static inline bool read_export_function_name(FILE* pe_file, PE_Information* megastructure_information, uint32_t name_index)
{
    return read_single_name(pe_file, megastructure_information->export_module_function_pointers[name_index], &(megastructure_information->export_module_functions[name_index]));
}

#endif