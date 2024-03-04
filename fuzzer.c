#include <stdio.h>
#include <stdlib.h>
#include "src/readpe.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FILE* test_file = fopen("./fuzzed.exe", "wb");
    if (test_file == NULL)
    {
        return 1;
    }
    fwrite(Data, sizeof(uint8_t), Size, test_file);
    fclose(test_file);


    srand(1);

    printf("start parsing a file of size %lu\n", Size);

    PE_Information* pe_information = read_pe("./fuzzed.exe", (uint16_t)rand());
    if(pe_information == NULL)
    {
        return 1;
    }

    printf("read success\n");

    free_megastructure(&pe_information);

    return 0;
}