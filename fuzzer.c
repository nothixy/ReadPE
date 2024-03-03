#include <stdio.h>
#include "src/readpe.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FILE* test_file = fopen("./test.exe", "wb");
    if (test_file == NULL)
    {
        return 1;
    }
    fwrite(Data, sizeof(uint8_t), Size, test_file);
    fclose(test_file);

    PE_Information* pe_information = read_pe("./test.exe");
    if(pe_information == NULL)
    {
        return 1;
    }

    free_megastructure(&pe_information);

    return 0;
}