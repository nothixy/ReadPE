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

    for (uint32_t i = 0; i < pe_information->image_import_count; i++)
    {
        printf("DLL = %s\n", pe_information->import_dll_names[i]);
        for (uint32_t j = 0; pe_information->image_lookup_descriptors[i][j] != (uint32_t) -1; j++)
        {
            printf("Function = %s\n", pe_information->import_function_names[i][j]);
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