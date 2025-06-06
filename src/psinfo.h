#define PRFNSZ          16
#define PRARGSZ         80

typedef struct psinfo {
        int     pr_flag;       
        int     pr_nlwp;       
        pid_t   pr_pid;         
        pid_t   pr_ppid;      
        pid_t   pr_pgid;       
        pid_t   pr_sid;       
        uid_t   pr_uid;       
        uid_t   pr_euid;      
        gid_t   pr_gid;         
        gid_t   pr_egid;        
        uintptr_t pr_addr;      
        size_t  pr_size;        
        size_t  pr_rssize;      
        size_t  pr_pad1;
        dev_t   pr_ttydev;                            
        ushort_t pr_pctcpu;     
        ushort_t pr_pctmem;
        timestruc_t pr_start;   
        timestruc_t pr_time;    
        timestruc_t pr_ctime;   
        char    pr_fname[PRFNSZ];      
        char    pr_psargs[PRARGSZ];    
        int     pr_wstat;       
        int     pr_argc;       
        uintptr_t pr_argv;      
        uintptr_t pr_envp;      
        char    pr_dmodel;      
        char    pr_pad2[3];   
        taskid_t pr_taskid;    
        projid_t pr_projid;     
        int     pr_nzomb;       
        poolid_t pr_poolid;     
        zoneid_t pr_zoneid;     
        id_t    pr_contract;   
        int     pr_filler[1];   
} psinfo_t;
