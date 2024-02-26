#include "readpe_internal.h"

#define IS_32_ORDINAL_FUNC(lookup_descriptor) ((lookup_descriptor >> 31) == 1)
#define IS_64_ORDINAL_FUNC(lookup_descriptor) ((lookup_descriptor >> 63) == 1)


bool read_dos_header(FILE* pe_file, PE_DOS_Header* dos_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(dos_header, sizeof(PE_DOS_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return dos_header->magic == DOS_HEADER_MAGIC;
}

bool read_coff_header(FILE* pe_file, PE_COFF_Header* coff_header)
{
    if (pe_file == NULL)
    {
        return false;
    }
    if(fread(coff_header, sizeof(PE_COFF_Header), 1, pe_file) <= 0)
    {
        return false;
    }
    return coff_header->magic == COFF_HEADER_MAGIC;
}

bool read_certificate(FILE* pe_file, PE_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[4].address, SEEK_SET);
    if(!is_seek_forward(ftell(pe_file)))
    {
        fprintf(stderr, "seek back forbidden !\n");
        return false;
    }
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
    int character_count = 0;
    int c;

    fseek(pe_file, seek_pos, SEEK_SET);
    if(!is_seek_forward(ftell(pe_file)))
    {
        fprintf(stderr, "seek back forbidden !\n");
        return false;
    }

    *name_addr = malloc(MAX_NAME_SIZE+1);
    
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


bool read_export_directory(FILE* pe_file, PE_Information* megastructure_information)
{
    fseek(pe_file, megastructure_information->directory_addresses[0].address, SEEK_SET);
    if(!is_seek_forward(ftell(pe_file)))
    {
        fprintf(stderr, "seek back forbidden !\n");
        return false;
    }

    if(fread(&(megastructure_information->image_export), sizeof(PE_Image_Export_Directory), 1, pe_file) <= 0)
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


int64_t read_lookup_descriptor(FILE* pe_file, PE_Information* megastructure_information)
{
    uint64_t lookup_descriptor;
    uint32_t lookup_descriptor32;

    if (megastructure_information->bits_64)
    {
        if(fread(&lookup_descriptor, sizeof(uint64_t), 1, pe_file) <= 0)
        {
            return READ_ERROR;
        }
        if (IS_64_ORDINAL_FUNC(lookup_descriptor))
        {
            return READ_IGNORE;
        }
    }
    else
    {
        if(fread(&lookup_descriptor32, sizeof(uint32_t), 1, pe_file) <= 0)
        {
            return READ_ERROR;
        }
        if (IS_32_ORDINAL_FUNC(lookup_descriptor32))
        {
            return READ_IGNORE;
        }
        lookup_descriptor = lookup_descriptor32;
    }

    uint32_t rva = lookup_descriptor & ((uint32_t) (1 << 31) - 1);
    if (rva == 0 && (!megastructure_information->bits_64 || (uint32_t) (lookup_descriptor >> 31) == 0))
    {
        return LOOKUP_DESCRIPTOR_END;
    }

    return find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, rva);
}