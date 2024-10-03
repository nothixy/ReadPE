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
    if(!seek_forward(pe_file, megastructure_information->directory_addresses[4].address))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }
    uint32_t filepos;
    do
    {
        megastructure_information->signature_length = safe_realloc(megastructure_information->signature_length, (megastructure_information->signature_count + 1) * sizeof(uint32_t));
        if(megastructure_information->signature_length == NULL)
        {
            return false;
        }
        megastructure_information->signature = safe_realloc(megastructure_information->signature, (megastructure_information->signature_count + 1) * sizeof(uint8_t*));
        if(megastructure_information->signature == NULL)
        {
            return false;
        }
        uint16_t version;
        uint16_t type;
        if(fread(&(megastructure_information->signature_length[megastructure_information->signature_count]), sizeof(uint32_t), 1, pe_file) <= 0)
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
            megastructure_information->signature_length[megastructure_information->signature_count] = 0;
            return true;  // no signature
        }
        if (type != CERTIFICATE_TYPE)
        {
            megastructure_information->signature_length[megastructure_information->signature_count] = 0;
            return true;  // no signature
        }
        if (megastructure_information->signature_length[megastructure_information->signature_count] < (2 * sizeof(uint16_t) + sizeof(uint32_t)))
        {
            return false;  // file corrupted
        }

        megastructure_information->signature_length[megastructure_information->signature_count] -= (2 * sizeof(uint16_t) + sizeof(uint32_t));
        megastructure_information->signature[megastructure_information->signature_count] = safe_malloc(megastructure_information->signature_length[megastructure_information->signature_count] * sizeof(uint8_t));
        if(megastructure_information->signature[megastructure_information->signature_count] == NULL)
        {
            return false;
        }
        if (fread(megastructure_information->signature[megastructure_information->signature_count], megastructure_information->signature_length[megastructure_information->signature_count] * sizeof(uint8_t), 1, pe_file) != 1)
        {
            megastructure_information->signature_count++;
            return false;
        }
        megastructure_information->signature_count++;
        filepos = (uint32_t) ftell(pe_file);
        if (filepos % 8 != 0)
        {
            filepos += 8 - (filepos % 8);
        }
    } while (filepos < megastructure_information->directory_addresses[4].address + megastructure_information->directory_addresses[4].size);
    return true;
}


bool read_single_name(FILE* pe_file, size_t seek_pos, char** name_addr)
{
    int character_count = 0;
    int c;

    if(!seek_forward(pe_file, seek_pos))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }

    *name_addr = safe_malloc(MAX_NAME_SIZE+1);
    if(*name_addr == NULL)
    {
        return false;
    }
    
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
    if(!seek_forward(pe_file, megastructure_information->directory_addresses[0].address))
    {
        fputs("Seek back forbidden !\n", stderr);
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
        megastructure_information->export_module_functions = safe_calloc(megastructure_information->image_export.name_count * sizeof(char*));
        if(megastructure_information->export_module_functions == NULL)
        {
            return false;
        }
        megastructure_information->export_module_function_pointers = safe_calloc(megastructure_information->image_export.name_count * sizeof(uint32_t));
        if(megastructure_information->export_module_function_pointers == NULL)
        {
            return false;
        }
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

    uint32_t rva = lookup_descriptor & ((uint32_t) (1U << 31) - 1);
    if (rva == 0 && (!megastructure_information->bits_64 || (uint32_t) (lookup_descriptor >> 31) == 0))
    {
        return LOOKUP_DESCRIPTOR_END;
    }

    return find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, rva);
}


bool read_resource_by_index(FILE* pe_file, PE_Information* megastructure_information, uint32_t index)
{
    if (!seek_forward(pe_file, megastructure_information->resource_information[index].data_rva))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }
    megastructure_information->resource_raw_data[index] = safe_calloc(megastructure_information->resource_information[index].size * sizeof(uint8_t));
    if(megastructure_information->resource_raw_data[index] == NULL)
    {
        return false;
    }
    return fread(megastructure_information->resource_raw_data[index], megastructure_information->resource_information[index].size * sizeof(uint8_t), 1, pe_file) == 1;
}


bool read_resource_data_entry(FILE* pe_file, PE_Information* megastructure_information, uint32_t data_entry_address)
{
    if (!seek_forward(pe_file, data_entry_address))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }
    megastructure_information->resource_information = safe_realloc(megastructure_information->resource_information, (megastructure_information->resource_count + 1) * sizeof(PE_Resource_Data_Entry));
    if(megastructure_information->resource_information == NULL)
    {
        return false;
    }
    megastructure_information->resource_raw_data = safe_realloc(megastructure_information->resource_raw_data, (megastructure_information->resource_count + 1) * sizeof(uint8_t*));
    if(megastructure_information->resource_raw_data == NULL)
    {
        return false;
    }
    megastructure_information->resource_raw_data[megastructure_information->resource_count] = NULL;
    if (fread(&megastructure_information->resource_information[megastructure_information->resource_count], sizeof(PE_Resource_Data_Entry), 1, pe_file) <= 0)
    {
        megastructure_information->resource_count++;
        return false;
    }
    megastructure_information->resource_information[megastructure_information->resource_count].data_rva = find_offset_from_rva(megastructure_information->section_count, megastructure_information->section_headers, megastructure_information->resource_information[megastructure_information->resource_count].data_rva);
    megastructure_information->resource_count++;
    return true;
}


bool read_resource_table_and_entries(FILE* pe_file, PE_Information* megastructure_information, uint32_t table_address)
{
    uint32_t first_bit_mask = (1U << 31);
    if(!seek_forward(pe_file, table_address))
    {
        fputs("Seek back forbidden !\n", stderr);
        return false;
    }
    megastructure_information->resource_tables = safe_realloc(megastructure_information->resource_tables, (megastructure_information->resource_table_count + 1) * sizeof(PE_Resource_Directory_Table));
    if(megastructure_information->resource_tables == NULL)
    {
        return false;
    }
    megastructure_information->resource_entries = safe_realloc(megastructure_information->resource_entries, (megastructure_information->resource_table_count + 1) * sizeof(PE_Resource_Directory_Entry*));
    if(megastructure_information->resource_entries == NULL)
    {
        return false;
    }
    fread(&megastructure_information->resource_tables[megastructure_information->resource_table_count], sizeof(PE_Resource_Directory_Table), 1, pe_file);
    uint32_t entry_count = megastructure_information->resource_tables[megastructure_information->resource_table_count].id_entry_count + megastructure_information->resource_tables[megastructure_information->resource_table_count].named_entry_count;
    megastructure_information->resource_entries[megastructure_information->resource_table_count] = safe_calloc(entry_count * sizeof(PE_Resource_Directory_Entry));
    if(megastructure_information->resource_entries[megastructure_information->resource_table_count] == NULL)
    {
        return false;
    }
    for (uint32_t i = 0; i < entry_count; i++)
    {
        if (fread(&megastructure_information->resource_entries[megastructure_information->resource_table_count][i], sizeof(PE_Resource_Directory_Entry), 1, pe_file) <= 0)
        {
            megastructure_information->resource_table_count++;
            return false;
        }
        uint32_t bit_on_if_offset_type_subdir = (megastructure_information->resource_entries[megastructure_information->resource_table_count][i].offset & first_bit_mask) ? 1 : 0;
        megastructure_information->resource_entries[megastructure_information->resource_table_count][i].id_or_name_or_store_offset_type = bit_on_if_offset_type_subdir;
        megastructure_information->resource_entries[megastructure_information->resource_table_count][i].offset &= (first_bit_mask - 1);
        megastructure_information->resource_entries[megastructure_information->resource_table_count][i].offset += megastructure_information->rsrc_base;
    }
    megastructure_information->resource_table_count++;
    return true;
}
