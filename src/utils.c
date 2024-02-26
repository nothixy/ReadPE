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
