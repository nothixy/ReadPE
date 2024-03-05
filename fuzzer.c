#include <stdio.h>
#include <stdlib.h>
#include "src/readpe.h"

uint16_t generate_random_flags(const uint8_t *data, size_t size)
{
    if(size < sizeof(uint16_t))
    {
        return PE_READ_EVERYTHING;
    }
    size /= sizeof(uint16_t);
    if(size > 100)
    {
        size = 100;
    }
    uint16_t r = 0;
    for(size_t i = 1; i <= size; i++)
    {
        r ^= ((uint16_t*)data)[size - i];
    }
    return  r;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FILE* test_file = fopen("./fuzzed.exe", "wb");
    if (test_file == NULL)
    {
        return 1;
    }
    fwrite(Data, sizeof(uint8_t), Size, test_file);
    fclose(test_file);

    uint16_t flags = (uint16_t)generate_random_flags(Data, Size);

    srand(1);

    printf("start parsing a file of size %lu with flags %d\n", Size, flags);

    PE_Information* pe_information = read_pe("./fuzzed.exe", flags);
    if(pe_information == NULL)
    {
        return 1;
    }

    printf("read success\n");

    free_megastructure(&pe_information);

    return 0;
}