#include <stdio.h>
#include "src/readpe.h"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fputs("Invalid number of arguments\n", stderr);
        return 1;
    }
    
    return !read_pe(argv[1]);
}