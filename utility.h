//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c


#ifndef PAMCSESSION_UTIL_H
#define PAMCSESSION_UTIL_H

#include "common.h"

#define StrLen(str) ( str ? strlen(str) : 0 )

int WriteToFile(const char *Path, const char *Str);
double FromSIUnit(const char *Data, int Base);

//Get items from the MatchList, and use them as fnmatch patterns, returning  TRUE
//if we find one that maches
int ItemMatches(const char *Item, const char *MatchList);
int ItemListMatches(const char *ItemList, const char *MatchList);

char *VCatStr(char *Dest, const char *Str1,  va_list args);
char *MCatStr(char *Dest, const char *Str1,  ...);
char *MCopyStr(char *Dest, const char *Str1,  ...);
char *CatStr(char *Dest, const char *Src);
char *CopyStr(char *Dest, const char *Src);
void StripTrailingWhitespace(char *str);
void StripLeadingWhitespace(char *str);
void StripQuotes(char *Str);
const char *GetTok(const char *In, char Delim, char **Token);
void Destroy(void *Item);
char *replace_char(char *str, char find, char replace);
int killAllInSession(char *procs);
#endif
