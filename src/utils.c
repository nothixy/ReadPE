#include "src/readpe_internal.h"

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


uint64_t get_min_addr(PE_Information* megastructure_information)
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

    return min_address;
}
