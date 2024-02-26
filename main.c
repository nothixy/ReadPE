#include <stdio.h>
#include "src/readpe.h"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fputs("Invalid number of arguments\n", stderr);
        return 1;
    }
    
    Megastructure_Information* megastructure_information = read_pe(argv[1]);
    if(megastructure_information == NULL)
    {
        return 1;
    }

    for (uint32_t i = 0; i < megastructure_information->image_import_count; i++)
    {
        fprintf(stdout, "DLL = %s\n", megastructure_information->import_dll_names[i]);
        for (uint32_t j = 0; megastructure_information->image_lookup_descriptors[i][j] != (uint32_t) -1; j++)
        {
            fprintf(stdout, "Function = %s\n", megastructure_information->import_function_names[i][j]);
        }
    }

    if (megastructure_information->export_module_name != NULL)
    {
        fprintf(stdout, "Module name = %s\n", megastructure_information->export_module_name);

        for (uint32_t i = 0; i < megastructure_information->image_export.name_count; i++)
        {
            fprintf(stdout, "Function = %s\n", megastructure_information->export_module_functions[i]);
        }
    }

    free_megastructure(&megastructure_information);

    return 0;
}