
#include <elf.h>
#include "psinfo.h"
int scan_disk_for_ehdrs(int fd);
int carve_elf32(off64_t offset);
bool validate_first_section_header(Elf32_Shdr *shdr, int shdr_num);
bool validate_elf32_core_ehdr(const Elf32_Ehdr *ehdr, off64_t offset, bool silent);
int get_file_size(Elf32_Shdr *shdr);
int write_elf32(Elf32_Ehdr *ehdr, ssize_t buffer_size, ssize_t file_size);
bool scan_block(int fd, off64_t starting_offset, off64_t block_offset, char *buffer, int buffer_size);
int process_offset_table(int fd);
void print_elf32_hdr(off64_t offset, const Elf32_Ehdr *hdr);
void print_elf32_shdr(off64_t offset, const Elf32_Shdr *shdr);
bool validate_psinfo_from_ptnote(Elf32_Ehdr *ehdr, ssize_t buffer_size, Elf32_Off offset, psinfo_t **ppsinfo);
void print_psinfo(psinfo_t *psinfo, Elf32_Off offset);
void print_usage(const char *program_name);
void * memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);
int probe_raw_device(int fd);
int is_corefile_enabled();

#define OFFSET_TABLE_SIZE 300
off64_t g_offset_table[OFFSET_TABLE_SIZE];
int g_offset_index = 0;

int w_no = 0;

#define BLOCK_INDEX(offset) ((offset) / (block_size))
#define BLOCK_OFFSET(offset) ((offset) % (block_size))
#define ROUND_SIZE(size) (((size + block_size - 1) / block_size) * block_size)
#define NEW_BUFFER_SIZE(offset, current_total) \
    (((offset) > (current_total)) ? (((offset) + (block_size) - 1) / (block_size)) * (block_size) : (current_total))

#define FILE_MB 1048576

#define GREEN_TEXT(text) (is_tty ? "\033[32m" text "\033[0m" : text)
#define RED_TEXT(text) (is_tty ? "\033[31m" text "\033[0m" : text)
#define CYAN_TEXT(text) (is_tty ? "\033[36m" text "\033[0m" : text)

#define ERROR_SUCCESS 0
#define ERROR_FATAL -1
#define ERROR_INFO -2

#define INTERVAL_BYTES  524288000 // 500MB
