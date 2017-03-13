#ifndef _LYDPC_STRUTIL_H_INCLUDED_
#define _LYDPC_STRUTIL_H_INCLUDED_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


 char * strutil_replace_insert(const char * source,int s,int e,const char * repstr);



 char * strutil_replace_insert(const char * source,int s,int e,const char * repstr){

    int repstrlen = strlen(repstr);
    int sourcelen = strlen(source);
    if(s>e || e>sourcelen){
        printf("error param in sutil_replace");
        return NULL;
    }

    char *buff = new char[sourcelen-(e-s)+repstrlen+10];
    // char buff[1024*512];

    memcpy(buff,source,s);
    memcpy(buff+s,repstr,repstrlen);
    memcpy(buff+s+repstrlen,source+e+1,sourcelen-e);

    return buff;
}









#endif
