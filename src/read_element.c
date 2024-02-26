#include "readpe_internal.h"


bool read_dos_header(FILE* pe_file, DOS_Header* dos_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(dos_header, sizeof(DOS_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return dos_header->magic == DOS_HEADER_MAGIC;
}

bool read_coff_header(FILE* pe_file, COFF_Header* coff_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(coff_header, sizeof(COFF_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return coff_header->magic == COFF_HEADER_MAGIC;
}

bool read_certificate(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[4].address, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    uint16_t version;
    uint16_t type;
    if(fread(&(megastructure_information->signature_length), sizeof(uint32_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if(fread(&version, sizeof(uint16_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if(fread(&type, sizeof(uint16_t), 1, pe_file) <= 0)
    {
        return false;
    }
    if (version != CERTIFICATE_VERSION)
    {
        megastructure_information->signature_length = 0;
        return true;  // no signature
    }
    if (type != CERTIFICATE_TYPE)
    {
        megastructure_information->signature_length = 0;
        return true;  // no signature
    }
    if (megastructure_information->signature_length < 8)
    {
        return false;  // file corrupted
    }

    megastructure_information->signature_length -= 8;
    megastructure_information->signature = malloc(megastructure_information->signature_length * sizeof(uint8_t));
    return fread(megastructure_information->signature, megastructure_information->signature_length * sizeof(uint8_t), 1, pe_file) == 1;
}


bool read_single_name(FILE* pe_file, size_t seek_pos, char** name_addr)
{
    fseek(pe_file, seek_pos, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    int character_count = 0;
    *name_addr = malloc(MAX_NAME_SIZE+1);
    int c;
    do
    {
        if((c = fgetc(pe_file)) == EOF)
        {
            return false;
        }
        (*name_addr)[character_count] = (char)c;
        character_count++;
    }
    while (c != 0 && character_count < MAX_NAME_SIZE);

    (*name_addr)[character_count] = '\0';

    return true;
}


bool read_export_directory(FILE* pe_file, Megastructure_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[0].address, SEEK_SET);
    assert(is_seek_forward(ftell(pe_file)));
    if(fread(&(megastructure_information->image_export), sizeof(Image_Export_Directory), 1, pe_file) <= 0)
    {
        return false;
    }
    megastructure_information->image_export.name = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name);
    megastructure_information->image_export.name_pointer = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->image_export.name_pointer);
    if (megastructure_information->image_export.name_count != 0)
    {
        megastructure_information->export_module_functions = calloc(megastructure_information->image_export.name_count, sizeof(char*));
        megastructure_information->export_module_function_pointers = calloc(megastructure_information->image_export.name_count, sizeof(uint32_t));
    }

    return true;
}