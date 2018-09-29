#include "common.h"
#include "utility.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <syslog.h>
#include <error.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

//Define which PAM interfaces we provide. In this case we are
//only going to provide a session interface, i.e. one
//that sets up things for, or related to, the logged in user
#define PAM_SM_SESSION
#define PAM_SM_ACCOUNT

// We do not supply these
/*
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
*/

// Include PAM headers
#include <security/pam_appl.h>
#include <security/pam_modules.h>


typedef struct
{
    char *CGroupDir;
    char *CSessionsDir;
    char *CGroupControllers;
    char *Users;
    unsigned int pids;
    unsigned int shares;
    int nice;
    unsigned int cpu_max;
    unsigned int files_max;
    double files_size;
    double mem_high;
    double mem_max;
    double swap_max;
    double proc_mem;
    double core_size;
} TSettings;


#define DEFAULT_CGROUP_DIR "/sys/fs/cgroup/"
#define DEFAULT_CGROUP_CONTROLLERS "+io,+memory,+pids"

int CGroupSetup(TSettings *Settings)
{
    pid_t pid;
    int result;
    char *Tempstr=NULL, *SessionDir=NULL, *Path=NULL;
    char *ptr=NULL;
    struct rlimit limit;
    DIR * dir=NULL;

    // enable controllers on toplevel (this could/should maybe be handled outside of the module)
    // or only once the module is initialised...
    Path=MCopyStr(Path, Settings->CGroupDir, "/cgroup.subtree_control", NULL);
    if(WriteToFile(Path, Settings->CGroupControllers) != TRUE){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write controllers (%s) to %s", Settings->CGroupControllers, Path);
    }

    dir=opendir(Settings->CSessionsDir);
    if(dir)
        closedir(dir);
    else if(errno == ENOENT){
        result=mkdir(Settings->CSessionsDir, 0700);
        if(result){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to create directory %s", Settings->CSessionsDir);
            return 1;
        }
        else{
            syslog(LOG_AUTHPRIV|LOG_DEBUG, "pam_csession: created directory %s", Settings->CSessionsDir);
        }
    }
    else{
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to open dir %s", Settings->CSessionsDir);
        return 2;
    }

    // enable controllers for our sub groups
    Path=MCopyStr(Path, Settings->CSessionsDir, "cgroup.subtree_control", NULL);
    if(WriteToFile(Path, Settings->CGroupControllers) != TRUE){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write controllers to %s", Path);
    }


    pid=getpid();
    SessionDir=(char *) realloc(SessionDir, 1024);
    snprintf(SessionDir, 1024, "%ssession-%d/", Settings->CSessionsDir, pid);
    result=mkdir(SessionDir, 0700);
    if(result){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to create session directory %s", SessionDir);
        return 3;
    }
    else{
        syslog(LOG_AUTHPRIV|LOG_DEBUG, "pam_csession: created session directory %s", SessionDir);
    }

    if (Settings->pids > 0)
    {
        Path=MCopyStr(Path, SessionDir, "pids.max",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        snprintf(Tempstr, 1024, "%d\n", Settings->pids);
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }

    //nice can be zero, it's not a limit, but rather a hint of processor
    //usage with '0' meaning 'normal sharing' so we can just allow
    //any value to be set here
    //if (Settings->nice > 0)
    {
        Path=MCopyStr(Path, SessionDir, "cpu.weight.nice",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        snprintf(Tempstr, 1024, "%d\n", nice);
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }

    if (Settings->shares > 0)
    {
        Path=MCopyStr(Path, SessionDir, "cpu.shares",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        snprintf(Tempstr, 1024, "%d\n", Settings->shares);
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }


    if (Settings->mem_high > 0)
    {
        Path=MCopyStr(Path, SessionDir, "memory.high",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        snprintf(Tempstr, 1024, "%f", Settings->mem_high);
        ptr=strrchr(Tempstr, '.');
        if (ptr) *ptr='\0';
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }

    if (Settings->mem_max > 0)
    {
        Path=MCopyStr(Path, SessionDir, "memory.max",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        ptr=strrchr(Tempstr, '.');
        if (ptr) *ptr='\0';
        snprintf(Tempstr, 1024, "%g\n", Settings->mem_max);
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }

    if (Settings->swap_max != 0)
    {
        Path=MCopyStr(Path, SessionDir, "memory.swap.max",NULL);
        Tempstr=(char *) realloc(Tempstr, 1024);
        ptr=strrchr(Tempstr, '.');
        if (ptr) *ptr='\0';
        if (Settings->swap_max < 0) Tempstr=CopyStr(Tempstr,"0");
        else snprintf(Tempstr, 1024, "%g\n", Settings->swap_max);
        if( WriteToFile(Path, Tempstr) != TRUE){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
        }
    }

    if (Settings->files_size > 0)
    {
        limit.rlim_cur=(rlim_t) Settings->files_size;
        limit.rlim_max=(rlim_t) Settings->files_size;
        if( setrlimit(RLIMIT_FSIZE, &limit) != 0){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to set RLIMIT_FSIZE to %d (%s)", Settings->files_size, strerror(errno));
        }
    }

    if (Settings->files_max > 0)
    {
        limit.rlim_cur=(rlim_t) Settings->files_max;
        limit.rlim_max=(rlim_t) Settings->files_max;
        if( setrlimit(RLIMIT_NOFILE, &limit) != 0){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to set RLIMIT_NOFILE to %d (%s)", Settings->files_max, strerror(errno));
        }
    }

    if (Settings->proc_mem > 0)
    {
        limit.rlim_cur=(rlim_t) Settings->proc_mem;
        limit.rlim_max=(rlim_t) Settings->proc_mem;
        if( setrlimit(RLIMIT_AS, &limit) != 0){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to set RLIMIT_AS to %d (%s)", Settings->proc_mem, strerror(errno));
        }
    }

    if (Settings->core_size > 0)
    {
        limit.rlim_cur=(rlim_t) Settings->core_size;
        limit.rlim_max=(rlim_t) Settings->core_size;
        if( setrlimit(RLIMIT_CORE, &limit) != 0){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to set RLIMIT_CORE to %d (%s)", Settings->core_size, strerror(errno));
        }
    }

    if (Settings->cpu_max > 0)
    {
        limit.rlim_cur=(rlim_t) Settings->cpu_max;
        limit.rlim_max=(rlim_t) Settings->cpu_max;
        if( setrlimit(RLIMIT_CPU, &limit) != 0){
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to set RLIMIT_CPU to %d (%s)", Settings->cpu_max, strerror(errno));
        }
    }

    //cgroup.procs is a list of processes within the cgroup. We add ourselves
    //to the list by writing '0' which means, 'add current process to cgroup'
    Path=MCopyStr(Path, SessionDir, "cgroup.procs",NULL);
    if( WriteToFile(Path, "0") != TRUE){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", "0", Path);
    }

    Destroy(SessionDir);
    Destroy(Tempstr);
    Destroy(Path);
}


//We do not provide any of the below functions, we could just leave them out
//but apparently it's considered good practice to supply them and return
//'PAM_IGNORE'

//PAM entry point for starting sessions. This is called after a user has
//passed all authentication. It allows a PAM module to perform certain tasks
//on login, like recording the login occured, or printing a message of the day
int csession_setup(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int i;
    const char *ptr;
    const char *p_user;
    TSettings Settings;

    memset(&Settings, 0, sizeof(TSettings));
    // defaults
    Settings.CGroupDir=CopyStr(Settings.CGroupDir, DEFAULT_CGROUP_DIR);
    Settings.CGroupControllers=CopyStr(Settings.CGroupControllers, DEFAULT_CGROUP_CONTROLLERS);
    int ret=0;

    /*
    //get the user. If something goes wrong we return PAM_IGNORE. This tells
    //pam that our module failed in some way, so ignore it. Perhaps we should
    //return PAM_PERM_DENIED to deny login, but this runs the risk of a broken
    //module preventing anyone from logging into the system!
    //perhaps there will not be a tty if we are logging in remotely
    pam_get_item(pamh, PAM_TTY, (const void **) &pam_tty);
    if (! pam_tty) pam_tty="";

    //perhaps there will not be a remote host if we are logging in locally
    pam_get_item(pamh, PAM_RHOST, (const void **) &pam_rhost);
    if (! pam_rhost) pam_rhost="";
    */


    pam_get_user(pamh, &p_user, NULL);

    for (i=0; i < argc; i++)
    {
        ptr=argv[i];

        if (strncmp(ptr,"cgroupfs=",9)==0)   Settings.CGroupDir=CopyStr(Settings.CGroupDir, ptr+9);
        else if (strncmp(ptr,"cgroupcontrollers=",18)==0)  Settings.CGroupControllers=CopyStr(Settings.CGroupControllers, ptr+18);
        else if (strncmp(ptr,"user=",5)==0)  Settings.Users=CopyStr(Settings.Users, ptr+5);
        else if (strncmp(ptr,"users=",6)==0)  Settings.Users=CopyStr(Settings.Users, ptr+6);
        else if (strncmp(ptr,"threads.max=",12)==0)  Settings.pids=strtoul(ptr+12, NULL, 10);
        else if (strncmp(ptr,"cpu.shares=",11)==0)  Settings.shares=strtoul(ptr+11, NULL, 10);
        else if (strncmp(ptr,"cpu.nice=",9)==0)  Settings.nice=atoi(ptr+9);
        else if (strncmp(ptr,"cpu.max=",8)==0)  Settings.cpu_max=strtoul(ptr+8, NULL, 10);
        else if (strncmp(ptr,"mem.high=",9)==0)  Settings.mem_high=FromSIUnit(ptr+9, 1024);
        else if (strncmp(ptr,"mem.max=",8)==0)   Settings.mem_max=FromSIUnit(ptr+8, 1024);
        else if (strncmp(ptr,"swap.max=",9)==0)
        {
            Settings.swap_max=FromSIUnit(ptr+9, 1024);
            //swap is a special case. If they actually specified '0' then we set it
            //to -1 to indicate swap is disabled
            if (Settings.swap_max==0) Settings.swap_max=-1;
        }
        else if (strncmp(ptr,"files.max=",10)==0)   Settings.files_max=FromSIUnit(ptr+10, 1024);
        else if (strncmp(ptr,"files.size=",11)==0)   Settings.files_size=FromSIUnit(ptr+11, 1024);
        else if (strncmp(ptr,"core.size=",10)==0)   Settings.core_size=FromSIUnit(ptr+10, 1024);
        else if (strncmp(ptr,"proc.mem=",9)==0)   Settings.proc_mem=FromSIUnit(ptr+9, 1024);
    }

	Settings.CGroupControllers=replace_char(Settings.CGroupControllers,',',' ');
    Settings.CSessionsDir=CopyStr(Settings.CSessionsDir, Settings.CGroupDir);
    Settings.CSessionsDir=CatStr(Settings.CSessionsDir, "/csessions/");

    if (ItemListMatches(p_user, Settings.Users)){
        if(CGroupSetup(&Settings) != 0)
            ret=1;
    }

    Destroy(Settings.CGroupDir);
    Destroy(Settings.Users);
    return ret;
}


void csession_cleanup(int argc, const char *argv[])
{
    const char *ptr;
    char *CGroupDir=NULL, *Path=NULL, *Tempstr=NULL;
    char *CSessionsDir=NULL;
    pid_t pid;
    int i;

    CGroupDir=CopyStr(CGroupDir, DEFAULT_CGROUP_DIR);

    for (i=0; i < argc; i++)
    {
        ptr=argv[i];
        if (strncmp(ptr,"cgroupfs=",9)==0) CGroupDir=CopyStr(CGroupDir, ptr+9);
    }
    CSessionsDir=CopyStr(CSessionsDir, CGroupDir);
    CSessionsDir=CatStr(CSessionsDir, "/csessions/");

    pid=getpid();
    Path=MCopyStr(Path, CGroupDir, "/cgroup.procs", NULL);
    Tempstr=(char *) realloc(Tempstr, 1024);
    snprintf(Tempstr, 1024, "%d", pid);
    if( WriteToFile(Path, Tempstr) != TRUE){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to write (%s) to %s", Tempstr, Path);
    }

    Path=(char *) realloc(Path, 1024);
    snprintf(Path, 1024, "%s/session-%d/", CSessionsDir, pid);
    if(rmdir(Path) != 0)
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: failed to remove session directory %s", Path);

    Destroy(CGroupDir);
    Destroy(Tempstr);
    Destroy(Path);
}


// PAM entry point for authentication. This function gets called by pam when
//a login occurs. argc and argv work just like argc and argv for the 'main'
//function of programs, except they pass in the options defined for this
//module in the pam configuration files in /etc/pam.conf or /etc/pam.d/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if(csession_setup(pamh, flags, argc, argv) != 0)
        return PAM_SESSION_ERR;
    return PAM_SUCCESS;
}

//PAM entry point for ending sessions. This is called when a user logs out
//It allows a PAM module to perform certain tasks on logout
//like recording the logout occured, or clearing up temporary files
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    csession_cleanup(argc, argv);
    return(PAM_IGNORE);
}

// PAM entry point for 'account management'. This decides whether a user
// who has already been authenticated by pam_sm_authenticate should be
// allowed to log in (it considers other things than the users password)
// Really this is what we should have used here
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}


//PAM entry point for setting 'credentials' or properties of the user
//If our module stores or produces extra information about a user (e.g.
//a kerberous ticket or geolocation value) then it will pass this information
//to a PAM aware program in this call
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}

// PAM entry point for changing passwords. If our module stores passwords
// then this will be called whenever one needs changing
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return(PAM_IGNORE);
}


//I couldn't find any documentation on this. I think it notifies PAM of our
//module name
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_csession");
#endif
