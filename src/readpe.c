#include "src/readpe_internal.h"

#define MAX_CERTIFICATE_NAME_SIZE 50
#define CERTIFICATE_BASE_OUTPUT_NAME "certificate"

#define MAX_RESOURCE_NAME_SIZE 50
#define RESOURCE_BASE_OUTPUT_NAME "resource"

enum SEARCH_RESPONSE {
    SEARCH_ERROR = -1,
    SEARCH_NOT_FOUND,
    SEARCH_FOUND
};

static inline bool is_last_image_import_descriptor(PE_Image_Import_Descriptor* descriptor)
{
    return descriptor->first_thunk == 0 && descriptor->forwarder_chain == 0 && descriptor->name == 0 && descriptor->something.original_first_thunk == 0 && descriptor->timestamp == 0;
}

static bool read_import_table(FILE* pe_file, PE_Information* megastructure_information)
{
    bool last_import_desc = false;

    if(!seek_forward(pe_file, megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_IMPORT].address))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }

    megastructure_information->image_imports = NULL;
    while (!last_import_desc)
    {
        PE_Image_Import_Descriptor import_descriptor;

        if(fread(&import_descriptor, sizeof(PE_Image_Import_Descriptor), 1, pe_file) <= 0)
        {
            return false;
        }

        last_import_desc = is_last_image_import_descriptor(&import_descriptor);

        if(!last_import_desc)
        {
            megastructure_information->image_imports = realloc(megastructure_information->image_imports, (megastructure_information->image_import_count + 1) * sizeof(PE_Image_Import_Descriptor));
            megastructure_information->image_imports[megastructure_information->image_import_count] = import_descriptor;

            megastructure_information->image_imports[megastructure_information->image_import_count].name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, import_descriptor.name);
            megastructure_information->image_imports[megastructure_information->image_import_count].something.original_first_thunk = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, import_descriptor.something.original_first_thunk);

            megastructure_information->image_import_count++;
        }
    }

    if (megastructure_information->image_import_count != 0)
    {
        megastructure_information->import_dll = calloc(megastructure_information->image_import_count, sizeof(PE_DLL));
        megastructure_information->image_lookup_descriptors = calloc(megastructure_information->image_import_count, sizeof(uint32_t*));
    }
    return true;
}


static bool read_import_lookup_descriptors(FILE* pe_file, PE_Information* megastructure_information, uint32_t import_index)
{
    if(!seek_forward(pe_file, megastructure_information->image_imports[import_index].something.original_first_thunk))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }

    int64_t x;
    int count = 0;
    megastructure_information->image_lookup_descriptors[import_index] = malloc(0);
    do
    {
        x = read_lookup_descriptor(pe_file, megastructure_information);

        if(x == READ_ERROR)
        {
            return false;
        }
        if(x == READ_IGNORE)
        {
            continue;
        }

        megastructure_information->image_lookup_descriptors[import_index] = (uint32_t*) realloc(megastructure_information->image_lookup_descriptors[import_index], (count + 1) * sizeof(uint32_t));
        
        megastructure_information->image_lookup_descriptors[import_index][count] = (uint32_t)x;
        count++;
    } while(x != LOOKUP_DESCRIPTOR_END);

    megastructure_information->import_dll[import_index].function_names = calloc(count, sizeof(char*));
    return true;
}

static bool read_export_function_name_pointers(FILE* pe_file, PE_Information* megastructure_information)
{
    if(!seek_forward(pe_file, megastructure_information->image_export.name))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }

    if(fread(megastructure_information->export_module_function_pointers, sizeof(uint32_t), megastructure_information->image_export.name_count, pe_file) <= 0)
    {
        return false;
    }
    for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
    {
        megastructure_information->export_module_function_pointers[i] = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->export_module_function_pointers[i]);
    }

    return true;
}


static enum SEARCH_RESPONSE search_addr_in_directory_addresses(FILE* pe_file, PE_Information* megastructure_information, uint64_t min_address)
{
    for (int i = 0; i < IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
    {
        if (megastructure_information->directory_addresses[i].address != min_address)
        {
            continue;
        }
        switch (i)
        {
            case IMAGE_DIRECTORY_ENTRY_EXPORT:
                if(!read_export_directory(pe_file, megastructure_information))
                {
                    return SEARCH_ERROR;
                }
                megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_EXPORT].address = 0;
                break;
            case IMAGE_DIRECTORY_ENTRY_IMPORT:
                if(!read_import_table(pe_file, megastructure_information))
                {
                    return SEARCH_ERROR;
                }
                megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_IMPORT].address = 0;
                break;
            case IMAGE_DIRECTORY_ENTRY_SECURITY:
                if(!read_certificate(pe_file, megastructure_information))
                {
                    return SEARCH_ERROR;
                }
                megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_SECURITY].address = 0;
                break;
            case IMAGE_DIRECTORY_ENTRY_RESOURCE:
                return SEARCH_NOT_FOUND;
            default:
                return SEARCH_ERROR;  // this is not supposed to happened
        }
        return SEARCH_FOUND;
    }
    return SEARCH_NOT_FOUND;
}

static enum SEARCH_RESPONSE search_addr_in_lookup_descriptors(FILE* pe_file, PE_Information* megastructure_information, uint64_t min_address, uint16_t index)
{
    if (megastructure_information->image_lookup_descriptors[index] == NULL)
    {
        return SEARCH_NOT_FOUND;
    }
    
    for (uint32_t j = 0; megastructure_information->image_lookup_descriptors[index][j] != LOOKUP_DESCRIPTOR_END; j++)
    {
        if (megastructure_information->image_lookup_descriptors[index][j] == min_address)
        {
            if(!read_import_function_name(pe_file, megastructure_information, index, j))
            {
                return SEARCH_ERROR;
            }
            megastructure_information->image_lookup_descriptors[index][j] = 0;
            return SEARCH_FOUND;
        }
    }
    return SEARCH_NOT_FOUND;
}

static enum SEARCH_RESPONSE search_addr_in_image_imports(FILE* pe_file, PE_Information* megastructure_information, uint64_t min_address)
{
    if (megastructure_information->image_imports == NULL)
    {
        return SEARCH_NOT_FOUND;
    }
    for (uint16_t i = 0; i < megastructure_information->image_import_count; i++)
    {
        enum SEARCH_RESPONSE x;

        if (megastructure_information->image_imports[i].something.original_first_thunk == min_address)
        {
            if(!read_import_lookup_descriptors(pe_file, megastructure_information, i))
            {
                return SEARCH_ERROR;
            }
            megastructure_information->image_imports[i].something.original_first_thunk = 0;
            return SEARCH_FOUND;
        }
        if (megastructure_information->image_imports[i].name == min_address)
        {
            if(!read_import_dll_name(pe_file, megastructure_information, i))
            {
                return SEARCH_ERROR;
            }
            megastructure_information->image_imports[i].name = 0;
            return SEARCH_FOUND;
        }

        x = search_addr_in_lookup_descriptors(pe_file, megastructure_information, min_address, i);
        if(x != SEARCH_NOT_FOUND)
        {
            return x;
        }
    }

    return SEARCH_NOT_FOUND;
}

static enum SEARCH_RESPONSE search_addr_in_export_module(FILE* pe_file, PE_Information* megastructure_information, uint64_t min_address)
{
    if (megastructure_information->export_module_function_pointers == NULL)
    {
        return SEARCH_NOT_FOUND;
    }

    for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
    {
        if (megastructure_information->export_module_function_pointers[i] == min_address)
        {
            if(!read_export_function_name(pe_file, megastructure_information, i))
            {
                return SEARCH_ERROR;
            }
            megastructure_information->export_module_function_pointers[i] = 0;
            return SEARCH_FOUND;
        }
    }

    return SEARCH_NOT_FOUND;
}

static enum SEARCH_RESPONSE search_addr_in_resource_entry(FILE* pe_file, PE_Information* megastructure_information, uint64_t min_address)
{
    if (megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_RESOURCE].address == min_address)
    {
        if (!read_resource_table_and_entries(pe_file, megastructure_information, min_address))
        {
            return SEARCH_ERROR;
        }
        megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_RESOURCE].address = 0;
        return SEARCH_FOUND;
    }
    for (uint32_t i = 0; i < megastructure_information->resource_table_count; i++)
    {
        uint32_t current_table_entry_count = megastructure_information->resource_tables[i].id_entry_count + megastructure_information->resource_tables[i].named_entry_count;
        for (uint32_t j = 0; j < current_table_entry_count; j++)
        {
            if (megastructure_information->resource_entries[i][j].offset == min_address)
            {
                if (megastructure_information->resource_entries[i][j].id_or_name_or_store_offset_type != 0)
                {
                    if (!read_resource_table_and_entries(pe_file, megastructure_information, megastructure_information->resource_entries[i][j].offset))
                    {
                        return SEARCH_ERROR;
                    }
                }
                else
                {
                    if (!read_resource_data_entry(pe_file, megastructure_information, megastructure_information->resource_entries[i][j].offset))
                    {
                        return SEARCH_ERROR;
                    }
                }
                megastructure_information->resource_entries[i][j].offset = 0;
                return SEARCH_FOUND;
            }
        }
    }
    for (uint32_t i = 0; i < megastructure_information->resource_count; i++)
    {
        if (megastructure_information->resource_information[i].data_rva == min_address)
        {
            if (!read_resource_by_index(pe_file, megastructure_information, i))
            {
                return SEARCH_ERROR;
            }
            megastructure_information->resource_information[i].data_rva = 0;
            return SEARCH_FOUND;
        }
    }

    return SEARCH_NOT_FOUND;
}

static bool read_all_data(FILE* pe_file, PE_Information* megastructure_information)
{
    uint64_t min_address;
    while ((min_address = get_min_addr(megastructure_information)) != (uint64_t)(-1))
    {
        enum SEARCH_RESPONSE x;
        
        x = search_addr_in_directory_addresses(pe_file, megastructure_information, min_address);
        if(x == SEARCH_FOUND)
        {
            continue;
        }
        if(x == SEARCH_ERROR)
        {
            return false;
        }

        x = search_addr_in_image_imports(pe_file, megastructure_information, min_address);
        if(x == SEARCH_FOUND)
        {
            continue;
        }
        if(x == SEARCH_ERROR)
        {
            return false;
        }
        
        if (megastructure_information->image_export.name == min_address)
        {
            if(!read_export_module_name(pe_file, megastructure_information))
            {
                return false;
            }
            megastructure_information->image_export.name = 0;
            continue;
        }
        if (megastructure_information->image_export.name_pointer == min_address)
        {
            if(!read_export_function_name_pointers(pe_file, megastructure_information))
            {
                return false;
            }
            megastructure_information->image_export.name_pointer = 0;
            continue;
        }

        x = search_addr_in_export_module(pe_file, megastructure_information, min_address);
        if(x == SEARCH_FOUND)
        {
            continue;
        }
        if(x == SEARCH_ERROR)
        {
            return false;
        }

        x = search_addr_in_resource_entry(pe_file, megastructure_information, min_address);
        if(x == SEARCH_FOUND)
        {
            continue;
        }
        if (x == SEARCH_ERROR)
        {
            return false;
        }

        return false;  // addr not found, file corrupted
    }

    return true;
}



PE_Information* read_pe(const char* filename)
{
    PE_Information* megastructure_information = NULL;
    PE_Optional_Header pe_optional_header;
    pe_optional_header.data_directory = NULL;
    PE_COFF_Header coff_header;
    PE_DOS_Header dos_header;
    FILE* pe_file = fopen(filename, "r");
    if (pe_file == NULL)
    {
        fputs("Error: can't open file\n", stderr);
        goto ERROR;
    }
    if (!read_dos_header(pe_file, &dos_header))
    {
        fputs("Error: invalid DOS header\n", stderr);
        goto ERROR;
    }
    if(!seek_forward(pe_file, dos_header.lfa_new))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }
    if (!read_coff_header(pe_file, &coff_header))
    {
        fputs("Error: invalid COFF header\n", stderr);
        goto ERROR;
    }
    if (coff_header.optional_header_size == 0)
    {
        fputs("Error: this file doesn't have an optional header, I don't know how to proceed\n", stderr);
        goto ERROR;
    }
    if(fread(&pe_optional_header, offsetof(PE_Optional_Header, stack_reserved_size), 1, pe_file) <= 0)
    {
        fputs("Error: file corrupted\n", stderr);
        goto ERROR;
    }
    if (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_64)
    {
        if(fread(&(pe_optional_header.stack_reserved_size), sizeof(uint64_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.stack_commit_size), sizeof(uint64_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.heap_reserve_size), sizeof(uint64_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.heap_commit_size), sizeof(uint64_t), 1, pe_file) <= 0)
        {
            fputs("Error: file corrupted\n", stderr);
            goto ERROR;
        }
    }
    else if (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_32)
    {
        if(fread(&(pe_optional_header.stack_reserved_size), sizeof(uint32_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.stack_commit_size), sizeof(uint32_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.heap_reserve_size), sizeof(uint32_t), 1, pe_file) <= 0
            || fread(&(pe_optional_header.heap_commit_size), sizeof(uint32_t), 1, pe_file) <= 0)
        {
            fputs("Error: file corrupted\n", stderr);
            goto ERROR;
        }
    }
    else
    {
        fputs("Error: this tool only supports PE executable files\n", stderr);
        goto ERROR;
    }

    megastructure_information = (PE_Information*) calloc(1, sizeof(PE_Information));

    if(fread(&(pe_optional_header.loader_flags), sizeof(uint32_t), 1, pe_file) <= 0
        || fread(&(pe_optional_header.rva_number_size), sizeof(uint32_t), 1, pe_file) <= 0
        || fread(megastructure_information->directory_addresses, sizeof(PE_Data_Directory), IMAGE_DIRECTORY_ENTRY_NB_ARGS, pe_file) <= 0)
    {
        fputs("Error: file corrupted\n", stderr);
        goto ERROR;
    }

    if (pe_optional_header.rva_number_size > IMAGE_DIRECTORY_ENTRY_NB_ARGS)
    {
        if(!seek_forward(pe_file, (pe_optional_header.rva_number_size - IMAGE_DIRECTORY_ENTRY_NB_ARGS) * sizeof(PE_Data_Directory)))
        {
            fputs("Seek back forbidden !\n", stderr);
            goto ERROR;
        }
    }

    megastructure_information->section_headers = malloc(coff_header.section_count * sizeof(PE_Section_Header));
    if (megastructure_information->section_headers == NULL)
    {
        fputs("An error has occurred\n", stderr);
        goto ERROR;
    }
    if(fread(megastructure_information->section_headers, sizeof(PE_Section_Header), coff_header.section_count, pe_file) <= 0)
    {
        fputs("Error: file corrupted\n", stderr);
        goto ERROR;
    }

    megastructure_information->section_count = coff_header.section_count;

    for (int i = 0; i < IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
    {
        if (i != IMAGE_DIRECTORY_ENTRY_SECURITY)  // because security is an absolute addr
        {
            megastructure_information->directory_addresses[i].address = find_offset_from_rva(coff_header.section_count, megastructure_information->section_headers, megastructure_information->directory_addresses[i].address);
        }

        // Temporary because I can't parse other information
        if (i != IMAGE_DIRECTORY_ENTRY_EXPORT && i != IMAGE_DIRECTORY_ENTRY_IMPORT && i != IMAGE_DIRECTORY_ENTRY_SECURITY && i != IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            megastructure_information->directory_addresses[i].address = 0;
        }
    }

    megastructure_information->rsrc_base = megastructure_information->directory_addresses[IMAGE_DIRECTORY_ENTRY_RESOURCE].address;
    megastructure_information->bits_64 = (pe_optional_header.signature == PE_OPTIONAL_HEADER_SIGNATURE_64);

    if(!read_all_data(pe_file, megastructure_information))
    {
        fputs("Error: file corrupted\n", stderr);
        goto ERROR;
    }

    char resource_filepath[MAX_RESOURCE_NAME_SIZE] = RESOURCE_BASE_OUTPUT_NAME;
    for (uint32_t i = 0; i < megastructure_information->resource_count; i++)
    {
        memset(&resource_filepath[sizeof(RESOURCE_BASE_OUTPUT_NAME) - 1], 0, MAX_RESOURCE_NAME_SIZE - sizeof(RESOURCE_BASE_OUTPUT_NAME) + 1);
        sprintf(&resource_filepath[sizeof(RESOURCE_BASE_OUTPUT_NAME) - 1], "%010u", i);

        FILE* res = fopen(resource_filepath, "wb");
        if (res != NULL)
        {
            fwrite(megastructure_information->resource_raw_data[i], sizeof(uint8_t), megastructure_information->resource_information[i].size, res);
            fclose(res);
        }
        else
        {
            fprintf(stderr, "Can't write resource file to %s, ignoring\n", resource_filepath);
        }
    }

    char certificate_filepath[MAX_CERTIFICATE_NAME_SIZE] = CERTIFICATE_BASE_OUTPUT_NAME;
    for (uint32_t i = 0; i < megastructure_information->signature_count; i++)
    {
        memset(&certificate_filepath[sizeof(CERTIFICATE_BASE_OUTPUT_NAME)-1], 0, MAX_CERTIFICATE_NAME_SIZE - sizeof(CERTIFICATE_BASE_OUTPUT_NAME) + 1);
        sprintf(&certificate_filepath[sizeof(CERTIFICATE_BASE_OUTPUT_NAME)-1], "%010u.der", i);

        FILE* cert = fopen(certificate_filepath, "wb");
        if (cert != NULL)
        {
            fwrite(megastructure_information->signature[i], sizeof(uint8_t), megastructure_information->signature_length[i], cert);
            fclose(cert);
        }
        else
        {
            fprintf(stderr, "Can't write certificate file to %s, ignoring\n", certificate_filepath);
        }
    }


    if(pe_file != NULL)
        fclose(pe_file);

    return megastructure_information;

ERROR:
    free_megastructure(&megastructure_information);
    if(pe_file != NULL)
        fclose(pe_file);
    
    return NULL;
}

void free_dll_functions(PE_DLL* dll)
{
    if(dll == NULL || dll->function_names == NULL)
    {
        return;
    }

    for(uint32_t i = 0; i < dll->function_number; i++)
    {
        free(dll->function_names[i]);
    }
}


void free_megastructure(PE_Information** pps)
{
    if(*pps == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < (*pps)->signature_count; i++)
    {
        free((*pps)->signature[i]);
    }
    free((*pps)->signature_length);
    free((*pps)->signature);
    free((*pps)->section_headers);
    if ((*pps)->import_dll != NULL)
    {
        for (uint32_t i = 0; i < (*pps)->image_import_count; i++)
        {
            free_dll_functions(&((*pps)->import_dll[i]));
        }
    }
    if ((*pps)->image_lookup_descriptors != NULL)
    {
        for (uint32_t i = 0; i < (*pps)->image_import_count; i++)
        {
            free(((*pps)->image_lookup_descriptors)[i]);
        }
    }
    if ((*pps)->export_module_functions != NULL)
    {
        for (uint32_t i = 0; i < (*pps)->image_export.name_count; i++)
        {
            free((*pps)->export_module_functions[i]);
        }
    }
    for (uint32_t i = 0; i < (*pps)->resource_table_count; i++)
    {
        free((*pps)->resource_entries[i]);
    }
    for (uint32_t i = 0; i < (*pps)->resource_count; i++)
    {
        free((*pps)->resource_raw_data[i]);
    }
    free((*pps)->resource_raw_data);
    free((*pps)->resource_entries);
    free((*pps)->resource_tables);
    free((*pps)->resource_information);
    free((*pps)->export_module_function_pointers);
    free((*pps)->export_module_functions);
    free((*pps)->export_module_name);
    free((*pps)->image_imports);
    free((*pps)->import_dll);
    free((*pps)->image_lookup_descriptors);

    free(*pps);
    *pps = NULL;
}