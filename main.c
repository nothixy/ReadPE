#include <stdio.h>
#include "src/readpe.h"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fputs("Invalid number of arguments\n", stderr);
        return 1;
    }
    
    PE_Information* pe_information = read_pe(argv[1]);
    if(pe_information == NULL)
    {
        return 1;
    }


    PE_DLL dll;

    for(uint16_t i = 0; pe_get_dll(pe_information, &dll, i); i++)
    {
        printf("DLL = %s index = %d\n", dll.name, dll._index);
        if(pe_information->import_function_names[dll._index] == NULL)
        {
            continue;
        }
        for (uint32_t j = 0; pe_information->import_function_names[dll._index][j] != NULL; j++)
        {
            printf("Function = %s\n", pe_information->import_function_names[dll._index][j]);
        }
    }

    if (pe_information->export_module_name != NULL)
    {
        printf("Module name = %s\n", pe_information->export_module_name);

        for (uint32_t i = 0; i < pe_information->image_export.name_count; i++)
        {
            printf("Function = %s\n", pe_information->export_module_functions[i]);
        }
    }

    free_megastructure(&pe_information);

    return 0;
}