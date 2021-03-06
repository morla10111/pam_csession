//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c

#include "utility.h"
#include <fnmatch.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>

int WriteToFile(const char *Path, const char *Str)
{
    int fd;

    fd=open(Path, O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
    if (fd == -1){
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: open failed for %s (%s)", Path,strerror(errno));
        return(FALSE);
    }
    if(write(fd, Str, strlen(Str)) != strlen(Str)){
        close(fd);
        return(FALSE);
    }
    if(close(fd) != 0)
        return(FALSE);

    return(TRUE);
}


//Get items from the MatchList, and use them as fnmatch patterns, returning  TRUE
//if we find one that matches. However, if the match pattern starts with '!', then
//return TRUE if the match fails
int ItemMatches(const char *Item, const char *MatchList)
{
    const char *ptr, *mptr;
    char *Match=NULL;
    int result=FALSE;

    if (StrLen(Item) ==0) return(FALSE);
    ptr=GetTok(MatchList, ',', &Match);
    while (ptr)
    {
        mptr=Match;
        if (*mptr=='!') mptr++;
        if (fnmatch(mptr, Item, 0)==0)
        {
            if (*Match!='!')
            {
                result=TRUE;
                break;
            }
        }
        else if (*Match=='!')
        {
            result=TRUE;
            break;
        }
        ptr=GetTok(ptr, ',', &Match);
    }

    Destroy(Match);

    return(result);
}



//call 'ItemMatches' for each item in the list 'ItemList'
int ItemListMatches(const char *ItemList, const char *MatchList)
{
    char *Item=NULL;
    const char *ptr;
    int result=FALSE;

    if (! StrLen(MatchList)) return(TRUE);

    ptr=GetTok(ItemList, ' ', &Item);
    while (ptr)
    {
        if (ItemMatches(Item, MatchList))
        {
            result=TRUE;
            break;
        }
        ptr=GetTok(ptr, ' ', &Item);
    }

    Destroy(Item);

    return(result);
}



double ToPower(double val, double power)
{
    double result=0;
    int i;

    result=val;
    for (i=1; i < power; i++)
    {
        result=result * val;
    }

    return(result);
}


double FromSIUnit(const char *Data, int Base)
{
    double val;
    char *ptr=NULL;

    val=strtod(Data,&ptr);
    while (isspace(*ptr)) ptr++;
    switch (*ptr)
    {
        case 'k':
            val=val * Base;
            break;
        case 'M':
            val=val * ToPower(Base,2);
            break;
        case 'G':
            val=val * ToPower(Base,3);
            break;
        case 'T':
            val=val * ToPower(Base,4);
            break;
        case 'P':
            val=val * ToPower(Base,5);
            break;
        case 'E':
            val=val * ToPower(Base,6);
            break;
        case 'Z':
            val=val * ToPower(Base,7);
            break;
        case 'Y':
            val=val * ToPower(Base,8);
            break;
    }

    return(val);
}



#ifndef va_copy
#define va_copy(dest, src) (dest) = (src)
#endif

char *VCatStr(char *Dest, const char *Str1,  va_list args)
{
    //initialize these to keep valgrind happy
    size_t len=0;
    char *ptr=NULL;
    const char *sptr=NULL;


    if (Dest !=NULL)
    {
        len=StrLen(Dest);
        ptr=Dest;
    }
    else
    {
        len=10;
        ptr=(char *) calloc(10,1);
    }

    if (! Str1) return(ptr);
    for (sptr=Str1; sptr !=NULL; sptr=va_arg(args,const char *))
    {
        len+=StrLen(sptr)+1;
        len=len*2; // ?


        ptr=(char *) realloc(ptr,len);
        if (ptr && sptr) strcat(ptr,sptr);
    }

    return(ptr);
}


char *MCatStr(char *Dest, const char *Str1,  ...)
{
    char *ptr=NULL;
    va_list args;

    va_start(args,Str1);
    ptr=VCatStr(Dest,Str1,args);
    va_end(args);

    return(ptr);
}


char *MCopyStr(char *Dest, const char *Str1,  ...)
{
    char *ptr=NULL;
    va_list args;

    ptr=Dest;
    if (ptr) *ptr='\0';
    va_start(args,Str1);
    ptr=VCatStr(ptr,Str1,args);
    va_end(args);

    return(ptr);
}

char *CatStr(char *Dest, const char *Src)
{
    return(MCatStr(Dest,Src,NULL));
}


char *CopyStr(char *Dest, const char *Src)
{
    return(MCopyStr(Dest,Src,NULL));
}

void StripTrailingWhitespace(char *str)
{
    size_t len;
    char *ptr;

    len=StrLen(str);
    if (len==0) return;
    for(ptr=str+len-1; (ptr >= str) && isspace(*ptr); ptr--) *ptr='\0';
}


void StripLeadingWhitespace(char *str)
{
    char *ptr, *start=NULL;

    if (! str) return;
    for(ptr=str; *ptr !='\0'; ptr++)
    {
        if ((! start) && (! isspace(*ptr))) start=ptr;
    }

    if (!start) start=ptr;
    memmove(str,start,ptr+1-start);
}



void StripQuotes(char *Str)
{
    int len;
    char *ptr, StartQuote='\0';

    ptr=Str;
    while (isspace(*ptr)) ptr++;

    if ((*ptr=='"') || (*ptr=='\''))
    {
        StartQuote=*ptr;
        len=StrLen(ptr);
        if ((len > 0) && (StartQuote != '\0') && (ptr[len-1]==StartQuote))
        {
            if (ptr[len-1]==StartQuote) ptr[len-1]='\0';
            memmove(Str,ptr+1,len);
        }
    }

}



//I don't trust strtok, it's not reentrant, and this handles quotes
const char *GetTok(const char *In, char Delim, char **Token)
{
    char quot;
    const char *ptr;
    int len;

    //When input is exhausted return null
    if ((! In) || (*In=='\0')) return(NULL);

    *Token=CopyStr(*Token,"");
    for (ptr=In; *ptr !='\0'; ptr++)
    {
        if (*ptr==Delim) break;
        else if ((*ptr=='"') || (*ptr=='\''))
        {
            quot=*ptr;
            ptr++;
            while ((*ptr != quot) && (*ptr != '\0')) ptr++;
        }
    }


    len=ptr-In;
    *Token=(char *) realloc(*Token, len+1);
    strncpy(*Token,In,len);
    (*Token)[len]='\0';
    StripQuotes(*Token);

    //if it's not '\0', then it must be a delim, so go past it
    if (*ptr !='\0') ptr++;

    //Don't return null if ptr=='\0' here, because there's probably
    //still something in Token
    return(ptr);
}



void Destroy(void *Item)
{
    if (Item) free(Item);
}

char* replace_char(char* str, char find, char replace){
    char *current_pos = strchr(str,find);
    while (current_pos){
        *current_pos = replace;
        current_pos = strchr(current_pos,find);
    }
    return str;
}

int killAllInSession(char *procs){
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    pid_t pid;

    fp = fopen(procs, "r");
    if (fp == NULL)
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: open failed for %s (%s)", procs, strerror(errno));
        return 1;
    while ((read = getline(&line, &len, fp)) != -1) {
        pid=atoi(line);
        syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: killing: %d", pid);
        if( kill(pid,9) != 0)
            syslog(LOG_AUTHPRIV|LOG_INFO, "pam_csession: could not kill pid %d (%s)", pid, strerror(errno));

    }

    fclose(fp);
    if (line)
        free(line);
    return 0;
}

