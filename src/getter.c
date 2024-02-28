#include "readpe_internal.h"


bool pe_get_dll(const PE_Information* pe_info, PE_DLL* dll, uint16_t dll_num)
{
    static uint16_t actual_dll_num = 0;
    static uint16_t actual_offset = 0;

    while(actual_offset > 0 && dll_num <= actual_dll_num)
    {
        if(pe_info->import_dll_names[actual_offset] != NULL)
        {
            actual_dll_num--;
        }
        actual_offset--;
    }

    while(actual_offset < pe_info->image_import_count && actual_dll_num <= dll_num)
    {
        if(pe_info->import_dll_names[actual_offset] != NULL)
        {
            actual_dll_num++;
        }
        actual_offset++;
    }
    actual_dll_num--;
    actual_offset--;

    if(actual_dll_num != dll_num)
    {
        return false;
    }

    dll->name = pe_info->import_dll_names[actual_offset];
    dll->_index = actual_offset;

    return true;
}

/*const char* pe_get_function(const PE_Information* pe_info, const PE_DLL* dll, uint32_t function_num)
{
    if(pe_info->image_lookup_descriptors[dll->_index] == NULL)
    {
        return NULL;
    }
    for (uint32_t j = 0; pe_info->image_lookup_descriptors[dll->_index][j] != (uint32_t) -1; j++)
    {
        printf("Function = %s\n", pe_info->import_function_names[dll->_index][j]);
    }
}*/