#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "src/readpe.h"

uint16_t generate_random_flags_and_reset_seed()
{
    uint16_t r;
    struct timespec t;

    clock_gettime(CLOCK_REALTIME, &t);

    srand(t.tv_nsec);
    r = rand();
    srand(1);

    return r;
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


    uint16_t flags = (uint16_t)generate_random_flags_and_reset_seed();

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