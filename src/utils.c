#ifdef FUZZER_COMPLIANT
    #include <stdlib.h>
#endif
#include "src/readpe_internal.h"

bool seek_forward(FILE* pe_file, uint32_t seek_addr)
{
    if (ftell(pe_file) > seek_addr)
    {
        #ifdef FUZZER_COMPLIANT
            if(rand()%1000 == 0)
            {
                return false;
            }
        #else
            return false;
        #endif
    }
    
    return fseek(pe_file, seek_addr, SEEK_SET) == 0;
}

uint32_t find_offset_from_rva(int section_count, PE_Section_Header* section_headers, uint32_t rva)
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

static uint64_t get_min_addr_image_lookup(PE_Information* megastructure_information, uint64_t min_address, uint16_t index)
{
    if (megastructure_information->image_lookup_descriptors[index] == NULL)
    {
        return min_address;
    }
    for (uint32_t j = 0; megastructure_information->image_lookup_descriptors[index][j] != LOOKUP_DESCRIPTOR_END; j++)
    {
        if (megastructure_information->image_lookup_descriptors[index][j] != 0 && megastructure_information->image_lookup_descriptors[index][j] < min_address)
        {
            min_address = megastructure_information->image_lookup_descriptors[index][j];
        }
    }

    return min_address;
}


static uint64_t get_min_addr_image_import(PE_Information* megastructure_information, uint64_t min_address)
{
    if (megastructure_information->image_imports == NULL)
    {
        return min_address;
    }
    for (uint16_t i = 0; i < megastructure_information->image_import_count; i++)
    {
        if (megastructure_information->image_imports[i].something.original_first_thunk != 0 && megastructure_information->image_imports[i].something.original_first_thunk < min_address)
        {
            min_address = megastructure_information->image_imports[i].something.original_first_thunk;
        }
        if (megastructure_information->image_imports[i].name != 0 && megastructure_information->image_imports[i].name < min_address)
        {
            min_address = megastructure_information->image_imports[i].name;
        }

        min_address = get_min_addr_image_lookup(megastructure_information, min_address, i);
    }

    return min_address;
}

static uint64_t get_min_addr_export_module(PE_Information* megastructure_information, uint64_t min_address)
{
    if (megastructure_information->export_module_function_pointers == NULL)
    {
        return min_address;
    }
    for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
    {
        if (megastructure_information->export_module_function_pointers[i] != 0 && megastructure_information->export_module_function_pointers[i] < min_address)
        {
            megastructure_information->export_module_function_pointers[i] = min_address;
        }
    }

    return min_address;
}

static uint64_t get_min_addr_resource_entry(PE_Information* megastructure_information, uint64_t min_address)
{
    uint32_t rsrc_address = megastructure_information->directory_addresses[_IMAGE_DIRECTORY_ENTRY_RESOURCE].address;
    if (rsrc_address != 0 && rsrc_address < min_address)
    {
        min_address = rsrc_address;
    }
    for (uint32_t i = 0; i < megastructure_information->resource_table_count; i++)
    {
        uint32_t current_table_entry_count = megastructure_information->resource_tables[i].id_entry_count + megastructure_information->resource_tables[i].named_entry_count;
        for (uint32_t j = 0; j < current_table_entry_count; j++)
        {
            if (megastructure_information->resource_entries[i][j].offset != 0 && megastructure_information->resource_entries[i][j].offset < min_address)
            {
                min_address = megastructure_information->resource_entries[i][j].offset;
            }
        }
    }
    for (uint32_t i = 0; i < megastructure_information->resource_count; i++)
    {
        if (megastructure_information->resource_information[i].data_rva != 0 && megastructure_information->resource_information[i].data_rva < min_address)
        {
            min_address = megastructure_information->resource_information[i].data_rva;
        }
    }
    return min_address;
}

uint64_t get_min_addr(PE_Information* megastructure_information)
{
    uint64_t min_address = (uint64_t) -1;
    for (int i = 0; i < _IMAGE_DIRECTORY_ENTRY_NB_ARGS; i++)
    {
        if (megastructure_information->directory_addresses[i].address != 0 && megastructure_information->directory_addresses[i].address < min_address)
        {
            min_address = megastructure_information->directory_addresses[i].address;
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

    min_address = get_min_addr_export_module(megastructure_information, min_address);

    min_address = get_min_addr_image_import(megastructure_information, min_address);

    min_address = get_min_addr_resource_entry(megastructure_information, min_address);

    return min_address;
}
