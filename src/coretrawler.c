// gcc -std=c99 -o coretrawler coretrawler.c
// ./coretrawler --disk_path=/dev/rdsk/c0d0s0 --core_path=/var/tmp/coregrave
// for file in /var/tmp/coregrave/*; do [ -f "$file" ] && cat /dev/null > "$file"; done

#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#define __EXTENSIONS__
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <errno.h>
#include <sys/statvfs.h>
#include "coretrawler.h"

bool verbose = false;
bool write_file = false;
bool check_shdrs = false;
const char *core_path = NULL;
const char *disk_path = NULL;
const char *filter_name = NULL;
unsigned long total_req_space = 0;
unsigned long block_size = 0;
unsigned long long device_size = 0;
off64_t starting_offset = 0;
off64_t end_offset = 0;
bool is_tty = false;

int main(int argc, char *argv[]) 
{
    int ret;
    int option_index = 0;
    int opt;
    char *endptr = NULL;

    static struct option long_options[] = 
    {
        {"disk_path", required_argument, 0, 'd'},
        {"debug", no_argument, 0, 'v'},
        {"write", no_argument, 0, 'w'},
        {"core_path", optional_argument, 0, 'c'},
        {"filter_name", optional_argument, 0, 'f'},
        {"offset", optional_argument, 0, 'o'},
        {"e_offset", optional_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:vwo:e:c:f:h", long_options, &option_index)) != -1) 
    {
        switch (opt) 
        {
            case 'd':
                disk_path = optarg;
                break;
            case 'v':
                verbose = true;
                break;
             case 'o':
                starting_offset = (off64_t)strtoll(optarg, &endptr, 0);
                if (errno != 0 || *endptr != NULL)
                {
                    fprintf(stderr, RED_TEXT("[-] Error: parsing offset argument: %s\n"), optarg);
                    return -1;
                }
                break;   
            case 'e':
                end_offset = (off64_t)strtoll(optarg, &endptr, 0);
                if (errno != 0 || *endptr != NULL)
                {
                    fprintf(stderr, RED_TEXT("[-] Error: parsing end offset argument: %s\n"), optarg);
                    return -1;
                }
                break;                                   
            case 'w':
                write_file = true;
                break;
            case 'f':
                filter_name = optarg;
                break;                
            case 'c':
                core_path = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return -1;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    is_corefile_enabled();
    
    if (isatty(fileno(stdout)))
        is_tty = true;

    if (disk_path == NULL) 
    {
        fprintf(stderr, "[-] Error: --disk_path is required.\n");
        print_usage(argv[0]);
        return -1;
    }

    if (core_path == NULL) 
        core_path = "./exhumedcores";

    int fd = open(disk_path, O_RDONLY);
    if (fd < 0) 
    {
        perror("[-] Error: Failed to open raw disk.\n");
        return -1;
    }

    ret = probe_raw_device(fd);
    if (ret != ERROR_SUCCESS)
        return ret;

    ret = scan_disk_for_ehdrs(fd);
    if (ret != ERROR_FATAL)
        ret = ERROR_SUCCESS;

   return ret;
}

void print_usage(const char *program_name) 
{
    printf("Usage: %s --disk_path <path> [--filter_name <name>] [--offset <start_offset>] [--e_offset <end_offset>] [--debug] [--core_path <path>] [--write-file]\n", program_name);
    printf("\nOptions:\n");
    printf("  -d --disk_path=<path>   Path to the raw disk device (required).\n");
    printf("  -v --debug              Enable debug output. Default is no.\n");
    printf("  -w --write_file         Write output core files. Default is no.\n");
    printf("  -f --filter_name=<name> Specify process name. Default all.\n");
    printf("  -o --offset=<offset>    Specify starting offset.\n");
    printf("  -e --e_offset=<offset>  Specify end offset.\n");
    printf("  -c --core_path=<path>   Path to the directory for output core files. Default is ./exhumedcores. You should choose a path on a different partition to disk_path.\n");
    exit(1);
}

int probe_raw_device(int fd)
{
    struct dk_minfo dev_info = {0};
    struct statvfs fs_info   = {0};

    if (ioctl(fd, DKIOCGMEDIAINFO, &dev_info) < 0) 
    {
        perror("[-] Error: ioctl DKIOCGMEDIAINFO failed\n");
        return ERROR_FATAL;

    }

    if (statvfs("/", &fs_info) < 0) 
    {
        perror("[-] Error: statvfs failed for mount point: /\n");
        return ERROR_FATAL;
    }

    block_size  = fs_info.f_bsize;
    device_size = (unsigned long long)dev_info.dki_capacity * dev_info.dki_lbsize;
    printf("[*] Device Capacity: %llu, Block Size: %lu\n", device_size, block_size);

    return ERROR_SUCCESS;
}

int scan_disk_for_ehdrs(int fd)
{
    bool bret;
    int ret = ERROR_SUCCESS;
    char block_buf[block_size];
    off64_t cur_offset = 0;
    ssize_t r_bytes;

    if (starting_offset != 0)
    {
        starting_offset = ((off64_t)BLOCK_INDEX(starting_offset) * block_size);
        printf("[*] Seeking to starting offset (rounded down to block size):  [0x%" PRIx64 ":%lld]\n", 
            starting_offset, starting_offset);
        if ((starting_offset % block_size != 0) || 
            (unsigned long long)starting_offset > device_size)
        {
            printf(RED_TEXT("[*] Invalid starting offset: [0x%" PRIx64 ":%lld]\n"), 
                starting_offset, starting_offset);
            return ERROR_FATAL;
        }       
       
        starting_offset = lseek64(fd, starting_offset, SEEK_SET);
        if (starting_offset < 0)
        {
            perror("[-] Error: lseek");
            return ERROR_FATAL;
        } 
       
    }

    while ((r_bytes = read(fd, block_buf, block_size)) > 0) 
    {
        bret = scan_block(fd, starting_offset, cur_offset, block_buf, r_bytes);
        if (bret == false)
        {
            printf(RED_TEXT("[*] Stopped scanning at [0x%" PRIx64 ":%lld]\n"), 
                starting_offset + cur_offset, starting_offset + cur_offset);
            break;
        }
        
        cur_offset += (size_t)r_bytes;

        if ((starting_offset + cur_offset) % INTERVAL_BYTES < (off64_t)device_size)
        {
            if (is_tty)
            {
                printf("\r[*] Scanning progress: %.2f%%. Found %d ELF32 headers.", 
                    (((double)(starting_offset + cur_offset) / (double)device_size) * 100), g_offset_index);
                fflush(stdout);
            }
        }

        if (end_offset && (starting_offset + cur_offset >= end_offset))
        {
            printf("[*] Hit end offset: [0x%" PRIx64 ":%lld].\n", 
                end_offset, end_offset);
            break;
        }
    }
    
    if (r_bytes < 0)
    {
        fprintf(stderr, RED_TEXT("[-] Error: read(%d, %d) failed: %s\n"), fd, block_size, strerror(errno));
        close(fd);
        return ERROR_FATAL;
    }

    close(fd);
    printf("\n");
  
    if (verbose)
    {
        printf("[*] Offset Table:\n");
        for (int i = 0; i < g_offset_index; i++)
            printf("[*] [0x%" PRIx64 ":%lld]\n", g_offset_table[i], g_offset_table[i]);
        printf("\n");
    }

    
    if (g_offset_index)
        ret = process_offset_table(fd);
    
    return ret;
        
}

bool scan_block(int fd, off64_t starting_offset, off64_t block_offset, char *buffer, int buffer_size)
{
    int i;
    bool silent = true;

    for (i = 0; i < buffer_size - sizeof(Elf32_Ehdr); i++) 
    {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)(buffer + i);
        if (((int)ehdr % sizeof(long)) != 0)
            continue;

        if (verbose)
            silent = false;
        if (validate_elf32_core_ehdr(ehdr, starting_offset + block_offset + i, silent) == true)
        {
            if (g_offset_index < OFFSET_TABLE_SIZE)
            {
                g_offset_table[g_offset_index++] = 
                    starting_offset + block_offset + i;
                if (verbose)
                {
                    off64_t dev_offset = lseek64(fd, 0, SEEK_CUR);
                    fprintf(stderr, CYAN_TEXT("[*] Device Offset: [0x%" PRIx64 ":%lld - 0x%" PRIx64 ":%lld], Offset: [0x%" PRIx64 ":%lld], index: [0x%x:%d]\n\n"), 
                        dev_offset - buffer_size, dev_offset - buffer_size,
                        dev_offset, dev_offset,
                        starting_offset + block_offset + i, 
                        starting_offset + block_offset + i,
                        i, i);
                }
            }
            else
            {
                fprintf(stderr, RED_TEXT("\n[-] Error: Too many cores! g_offset_table[300] full.\n"));
                return false;
            }
        }    
            
        i += sizeof(Elf32_Ehdr);
    }

    return true;
}


int process_offset_table(int fd)
{
    int ret = ERROR_INFO;

    for (int i = 0; i < g_offset_index; i++)
    {
        off64_t offset = g_offset_table[i];
        ret = carve_elf32(offset);
        if (ret == ERROR_FATAL)
            break;
    }

    if (total_req_space > 0 && ret == ERROR_SUCCESS)
        printf("[*] Total space taken up by core files: %u bytes\n", total_req_space);

    return ret;
}

int carve_elf32(off64_t offset)
{
    int fd = -1;
    int ret = ERROR_INFO;
    char *buffer = NULL;
    char *ptr = NULL;
    Elf32_Ehdr *ehdr = NULL;
    Elf32_Shdr *shdr = NULL;
    Elf32_Phdr *phdr = NULL;
    psinfo_t *psinfo = NULL;
    ssize_t buffer_size = 0;
    off_t read_offset = 0;
    off64_t block_index  = 0;
    off64_t block_offset = 0;

    fd = open(disk_path, O_RDONLY);
    if (fd < 0) 
    {
        perror("[-] Error: Failed to open raw disk");
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }

    block_index  = ((off64_t)BLOCK_INDEX(offset) * block_size);
    block_offset =  (off64_t)BLOCK_OFFSET(offset);

    if (verbose)
        printf("[*] Found core at: [0x%" PRIx64 ":%lld].\n[*] Seeking to block index: [0x%" PRIx64 ":%lld] and adding block offset: [0x%" PRIx64 ":%lld]\n", 
            offset, offset, block_index, block_index, block_offset, block_offset);
    
    // Need to seek in block size units
    offset = lseek64(fd, block_index, SEEK_SET);
    if (offset == -1)
    {
        perror("[-] Error: lseek");
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
   
    offset = block_index + block_offset;
    
   if (block_offset > block_size)
   {
        fprintf(stderr, RED_TEXT("[-] Error: Invalid block offset: %d\n"), block_offset);
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
   }

    buffer_size = ROUND_SIZE(sizeof(Elf32_Ehdr) + block_offset);
    if (verbose)
         printf("[*] Read buffer size: %d\n", buffer_size);

    buffer = malloc(buffer_size);
    if (buffer == NULL)
    {
        perror("[-] Error: malloc");
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
    ptr = buffer;

    ssize_t read_size;
    read_size = read(fd, buffer, buffer_size);
    
    if (read_size < 0)
    {
        fprintf(stderr, RED_TEXT("[-] Error: read(%d, %d) failed: %s\n"), fd, buffer_size, strerror(errno));
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }

    read_offset += read_size;
    if (read_offset > buffer_size)
    {
        fprintf(stderr, "[-] Error: Buffer full!\n");
        goto cleanup_and_exit;
    }
    ptr += read_offset;

    ehdr = (Elf32_Ehdr *)(char *)(buffer + block_offset);
    //print_elf32_hdr(offset, ehdr);

    ssize_t shdr_size = (ehdr->e_shentsize * ehdr->e_shnum);
    if (ehdr->e_shoff + shdr_size > FILE_MB) 
    {
        fprintf(stderr, RED_TEXT("[-] Error: Section Header Offset %d too big\n"), ehdr->e_shoff + shdr_size);
        print_elf32_hdr(offset, ehdr);
        printf("\n");
        goto cleanup_and_exit;
    }


    ssize_t phdr_size = (ehdr->e_phentsize * ehdr->e_phnum);
    ssize_t hdrs_total_size = sizeof(Elf32_Ehdr) + phdr_size + shdr_size;
    
    if (hdrs_total_size > FILE_MB)
    {
        fprintf(stderr, RED_TEXT("[-] Error: Total Header Size (%u) > 1MB\n"), hdrs_total_size);
        print_elf32_hdr(offset, ehdr);
        printf("\n");
        goto cleanup_and_exit;
    }    
    buffer_size = NEW_BUFFER_SIZE(hdrs_total_size, buffer_size);

    buffer = realloc(buffer, buffer_size);
    if (buffer == NULL)
    {
        perror("[-] Error: relloc");
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
    ehdr = (Elf32_Ehdr *)(char *)(buffer + block_offset);
    ptr  = buffer + read_offset;

    read_size = read(fd, ptr, buffer_size - read_offset);
    if (read_size < 0)
    {
        fprintf(stderr, RED_TEXT("[-] Error: read(%d, %d) failed: %s\n"), fd, buffer_size - read_offset, strerror(errno));
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
    read_offset += read_size;
    if (read_offset > buffer_size)
    {
        fprintf(stderr, "[-] Error: Buffer full!\n");
        goto cleanup_and_exit;
    }
    ptr += read_size;

    shdr = (Elf32_Shdr *)((char *)ehdr + ehdr->e_shoff);
    phdr = (Elf32_Phdr *)((char *)ehdr + ehdr->e_phoff);

    if (check_shdrs && validate_first_section_header(shdr, ehdr->e_shnum) == false)
    {
        fprintf(stderr, RED_TEXT("[-] Error: First Section Header not null\n"));
        print_elf32_hdr(offset, ehdr);
        printf("\n");
        goto cleanup_and_exit;
    }
 
    int i;
    ssize_t total_sect_size = 0;
    for (i = 0; i < ehdr->e_shnum; i++)
    {
        //printf("[*] Index: %d\n", i);
        //print_elf32_shdr(offset + (i * sizeof(Elf32_Shdr)), &shdr[i]);
        total_sect_size += shdr[i].sh_size;
    }

    if (verbose)
        printf("[*] Count: %d, Total Section Size: %d\n", i, total_sect_size);

    int j = 0;
    ssize_t total_prog_size = 0;
    Elf32_Off ptnote_offsets[2] = {0};
    for (i = 0; i < ehdr->e_phnum; i++)
    {
        total_prog_size += phdr[i].p_filesz;
        if (phdr[i].p_type == PT_NOTE)
        {
            if (j < 2)
                ptnote_offsets[j++] = phdr[i].p_offset;
            else
            {
                fprintf(stderr, RED_TEXT("[-] More than 2 PT_NOTE segmants found. Probably corrupt.\n"));
                print_elf32_hdr(offset, ehdr);
                printf("\n");
                goto cleanup_and_exit;
            }
        }
    }

    if (total_prog_size < 0)
    {
        fprintf(stderr, RED_TEXT("[-] Invalid Total Segment Size. Probably corrupt.\n"));
        print_elf32_hdr(offset, ehdr);
        printf("\n");
        goto cleanup_and_exit;  
    }

    ssize_t total_size = total_sect_size + total_prog_size + hdrs_total_size;


    if ((size_t)total_size > (FILE_MB * 50))
    {
         fprintf(stderr, RED_TEXT("[-] Error: Bad core size. Data corrupt.\n"));
         print_elf32_hdr(offset, ehdr);
         printf("\n");
         goto cleanup_and_exit;
    }

    // Use last ptnote segment
    if (j <= 0 || validate_psinfo_from_ptnote(ehdr, buffer_size, ptnote_offsets[j-1], &psinfo) == false)
    {
        fprintf(stderr, RED_TEXT("[-] Error: Invalid PT_NOTE section\n"));
        print_elf32_hdr(offset, ehdr);
        printf("\n");
        goto cleanup_and_exit;
    }

    // Filtering on name. Skip if not found, 
    if (filter_name && strcmp(psinfo->pr_fname, filter_name) != 0)
    {
        if (verbose)
        {
            printf("[*] %s not found. Skipping.\n", filter_name);
            print_psinfo(psinfo, ptnote_offsets[j-1]);
            printf("\n");
        }
        goto cleanup_and_exit;
    }

    if (verbose)
        printf("[*] Count: %d, Total Program Size: %d\n", i, total_prog_size);

    print_elf32_hdr(offset, ehdr);
    printf("\tTotal File Size: %d, PT_NOTE Segments: %d\n", total_sect_size + total_prog_size, j);   
    print_psinfo(psinfo, ptnote_offsets[j-1]);

    buffer_size = NEW_BUFFER_SIZE(total_size, buffer_size);
    buffer = realloc(buffer, buffer_size);
    if (buffer == NULL)
    {
        perror("[-] Error: relloc");
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
    
    ehdr = (Elf32_Ehdr *)(char *)(buffer + block_offset);
    ptr  = buffer + read_offset;

    read_size = read(fd, ptr, buffer_size - read_offset);
    if (read_size < 0)
    {
        fprintf(stderr, RED_TEXT("[-] Error: read(%d, %d) failed %s\n"), fd, buffer_size - read_offset, strerror(errno));
        ret = ERROR_FATAL;
        goto cleanup_and_exit;
    }
    read_offset += read_size;
    if (read_offset > buffer_size)
    {
        fprintf(stderr, "[-] Error: Buffer full!\n");
        goto cleanup_and_exit;
    }
    ptr += read_size;

    total_req_space += total_size;
    if (write_file == true)
    {
        if ((ret = write_elf32(ehdr, buffer_size, total_size)) != ERROR_SUCCESS)
        {
            fprintf(stderr, RED_TEXT("[-] Error: Failed to write coredump.\n"));
            goto cleanup_and_exit;
        }
    }

    printf("\n");
    ret = ERROR_SUCCESS;
    
cleanup_and_exit:
    if (fd > 0)
        close(fd);
    if (buffer != NULL)
        free(buffer);
    return ret;
}

bool validate_psinfo_from_ptnote(Elf32_Ehdr *ehdr, ssize_t buffer_size, Elf32_Off offset, psinfo_t **ppsinfo)
{
    psinfo_t *psinfo;

    if ((size_t)offset >= (size_t)buffer_size)
    {
        fprintf(stderr, RED_TEXT("[-] psinfo offset corrupt: 0x%p\n"), offset);
        return false;
    }

    psinfo = (psinfo_t *)((char *)ehdr + offset + 0x14);


    if (psinfo->pr_pid == 0 || psinfo->pr_pid == 0 || psinfo->pr_fname[0] == 0)
    {
        fprintf(stderr, RED_TEXT("[-] psinfo struct corrupt: 0x%p\n"), offset);
        return false;
    }

    //print_psinfo(psinfo, offset);
    *ppsinfo = psinfo;
    return true;
}


void print_psinfo(psinfo_t *psinfo, Elf32_Off offset)
{
    
    time_t start_time = psinfo->pr_start.tv_sec;
    char start_time_str[64];
    strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", localtime(&start_time));

    printf("[*] PsInfo: [ehdr+0x%x]\n", offset);
    printf(GREEN_TEXT("[+] Start Time: %s, Process Name: %s, Executable Path: %s\n    PID: %d, PPID: %d, UID: %d, GID: %d, TTY: %d\n"), 
        start_time_str,
        psinfo->pr_fname,
        psinfo->pr_psargs,
        psinfo->pr_pid,
        psinfo->pr_ppid,
        psinfo->pr_uid,
        psinfo->pr_gid,
        psinfo->pr_ttydev);
}

int create_path(const char *core_path) 
{
    struct stat st;
    
    if (core_path == NULL) 
    {
        fprintf(stderr, RED_TEXT("[-] Error: core_path is NULL\n"));
        return ERROR_FATAL;
    }

    if (stat(core_path, &st) == 0) 
    {
        if (S_ISDIR(st.st_mode)) 
        {
            if (access(core_path, W_OK) == 0) 
                return ERROR_SUCCESS;
            else 
            {
                fprintf(stderr, RED_TEXT("[-] Error: Directory %s is not writable.\n"), core_path);
                return ERROR_FATAL;
            }
        } 
        else 
        {
            fprintf(stderr, RED_TEXT("[-] Error: %s exists but is not a directory.\n"), core_path);
            return ERROR_FATAL;
        }
    } 
    else 
    {
        if (mkdir(core_path, 0755) == 0) 
            return ERROR_SUCCESS;
        else 
        {
            fprintf(stderr, RED_TEXT("[-] Error: Failed to create directory %s: %s\n"), core_path, strerror(errno));
            return ERROR_FATAL;
        }
    }
}

int write_elf32(Elf32_Ehdr *ehdr, ssize_t buffer_size, ssize_t file_size)
{
    int wfd;
    struct statvfs stat;
    int ret = ERROR_INFO;

    if ((ret = create_path(core_path)) < 0)
        return ret;

    char filename[1024] = {0};
    snprintf(filename, sizeof(filename)-1, "%s/coredump.%d", core_path, w_no++);

    if (statvfs(core_path, &stat) != 0) 
    {
        perror("[-] Error: statvfs");
        return ERROR_FATAL;
    }

    unsigned long long available_space = stat.f_bavail * stat.f_frsize;
    if ((unsigned long long)file_size + FILE_MB > available_space)
    {
        fprintf(stderr, RED_TEXT("[-] Out of disk space! Avaiable: %ull, Required: %ull\n"), 
            available_space, file_size);
        return ERROR_FATAL;
    }
                        
    wfd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (wfd < 0) 
    {
        perror("[-] Error: open\n");
        return ERROR_FATAL;
    }

    struct stat file_stat;
    if (fstat(wfd, &file_stat) == -1)
    {
        perror("[-] Error: fstat\n");
        close(wfd);
        return ERROR_FATAL;
    }

    if (!S_ISREG(file_stat.st_mode)) 
    {
        fprintf(stderr, RED_TEXT("[-] File %s is not a regular file. Aborting.\n"), filename); 
        close(wfd);
        return ERROR_FATAL;
    }
    
    ssize_t w_bytes; 
    w_bytes = write(wfd, ehdr, file_size);
    if (w_bytes < 0)
    {
        perror("[-] Write\n");
        close(wfd);
        return ERROR_FATAL;
    }
    
    close(wfd);

    fprintf(stderr, CYAN_TEXT("[+] Wrote %d bytes to %s\n\n"), file_size, filename);

    return ERROR_SUCCESS;  
}


bool validate_first_section_header(Elf32_Shdr *shdr, int shdr_num) 
{
    if (shdr->sh_type    != 0  || shdr->sh_name   != 0   || 
        shdr->sh_flags   != 0  || shdr->sh_addr   != 0   || 
        shdr->sh_size    != 0  || shdr->sh_offset != 0   ||
        shdr->sh_link    != 0  || shdr->sh_info   != 0   || 
        shdr->sh_entsize != 0 )
    {
        return false;
    }

    return true;
}

bool validate_elf32_core_ehdr(const Elf32_Ehdr *ehdr, off64_t offset, bool silent)
{
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && ehdr->e_type == ET_CORE) 
    {
        //if (offset % block_size != 0)
        if (offset % 4 != 0)
        {
            if (verbose)
                fprintf(stderr, "[-] Error: offset misaligned: 0x%" PRIx64 ":%lld\n", offset, offset);
            return false;
        }

        if (silent == false)
            print_elf32_hdr(offset, ehdr);

        if (ehdr->e_ident[EI_CLASS] == ELFCLASS32 &&      // 32bit
            ehdr->e_ident[EI_DATA] == ELFDATA2MSB &&      // MSB
            ehdr->e_ident[EI_VERSION] == EV_NONE  &&      // Current
            ehdr->e_machine == EM_SPARC &&                // Sparc
            ehdr->e_type == ET_CORE &&                    // Core
            ehdr->e_version == EV_CURRENT)                // Current
            //ehdr->e_shentsize  == sizeof(Elf32_Shdr))
        {
            if (verbose)
                fprintf(stderr, CYAN_TEXT("[*] Found core candidate. Adding to offset table.\n"));
            return true;
        }
    }
    return false;
}

void print_elf32_shdr(off64_t offset, const Elf32_Shdr *shdr) 
{
    printf("[*] Section Header: [0x%" PRIx64 ":%lld]\n", offset, offset);
    printf("  sh_name:      %u\n", shdr->sh_name);
    printf("  sh_type:      %u\n", shdr->sh_type);
    printf("  sh_flags:     0x%x\n", shdr->sh_flags);
    printf("  sh_addr:      0x%x\n", shdr->sh_addr);
    printf("  sh_offset:    0x%x\n", shdr->sh_offset);
    printf("  sh_size:      %u\n", shdr->sh_size);
    printf("  sh_link:      %u\n", shdr->sh_link);
    printf("  sh_info:      %u\n", shdr->sh_info);
    printf("  sh_addralign: %u\n", shdr->sh_addralign);
    printf("  sh_entsize:   %u\n", shdr->sh_entsize);
}

void print_elf32_hdr(off64_t offset, const Elf32_Ehdr *ehdr)
{
    printf("[*] [0x%" PRIx64 ":%lld] Found ELF header with e_ident: (%d %d %d) (e_machine: %d, e_type: %d, e_version: %d)\n\tSection Header Table Offset: 0x%x:%d, Number of Table Entries: %d, Table Entry Size: %d\n\tString Table Index: %d\n\tProgram Header Table Offset: 0x%x:%d, Number of Table Entries:: %d, Table Entry Size: %d\n",  
        offset, 
        offset,
        ehdr->e_ident[EI_CLASS],
        ehdr->e_ident[EI_DATA],
        ehdr->e_ident[EI_VERSION],
        ehdr->e_machine,
        ehdr->e_type,
        ehdr->e_version,
        ehdr->e_shoff,
        ehdr->e_shoff, 
        ehdr->e_shnum, 
        ehdr->e_shentsize,
        ehdr->e_shstrndx,
        ehdr->e_phoff,
        ehdr->e_phoff, 
        ehdr->e_phnum,
        ehdr->e_phentsize
    );
}

void * memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) 
{
    if (needle_len == 0) {
        return (void *)haystack;
    }

    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return (void *)(h + i);
        }
    }

    return NULL;
}

int is_corefile_enabled() 
{

    struct rlimit rlim;

    if (getrlimit(RLIMIT_CORE, &rlim) != 0) 
    {
        perror("[-] Error: getrlimit\n");
        return ERROR_INFO;
    }

    if (rlim.rlim_cur <= 0) 
    {
        fprintf(stderr, RED_TEXT("[-] Corefile limit: %d. Are you sure corefiles are enabled?\n"), rlim.rlim_cur); 
        return ERROR_INFO;
    }

    return ERROR_SUCCESS;
}
