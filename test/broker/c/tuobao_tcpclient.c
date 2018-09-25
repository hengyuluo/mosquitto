#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
 
#include "tuobao_tcpclient.h"
 
#define BUFFER_SIZE 1024
 
 
int tuobao_tcpclient_create(tuobao_tcpclient *pclient,const char *host, int port){
    struct hostent *he;
 
    if(pclient == NULL) return -1;
    memset(pclient,0,sizeof(tuobao_tcpclient));
 
    if((he = gethostbyname(host))==NULL){
        return -2;
    }
 
    pclient->remote_port = port;
    strcpy(pclient->remote_ip,inet_ntoa( *((struct in_addr *)he->h_addr) ));
 
    pclient->_addr.sin_family = AF_INET;
    pclient->_addr.sin_port = htons(pclient->remote_port);
    pclient->_addr.sin_addr = *((struct in_addr *)he->h_addr);
 
    if((pclient->socket = socket(AF_INET,SOCK_STREAM,0))==-1){
        return -3;
    }
 
    /*TODO:Ê·ñÃͷÅڴæ?*/
 
    return 0;
}
 
int tuobao_tcpclient_conn(tuobao_tcpclient *pclient){
    if(pclient->connected)
        return 1;
 
    if(connect(pclient->socket, (struct sockaddr *)&pclient->_addr,sizeof(struct sockaddr))==-1){
        return -1;
    }
 
    pclient->connected = 1;
 
    return 0;
}
 
int tuobao_tcpclient_recv(tuobao_tcpclient *pclient,char **lpbuff,int size){
    int recvnum=0,tmpres=0;
    char buff[BUFFER_SIZE];
 
    *lpbuff = NULL;
 
    while(recvnum < size || size==0){
        tmpres = recv(pclient->socket, buff,BUFFER_SIZE,0);
        if(tmpres <= 0)
            break;
        recvnum += tmpres;
 
        if(*lpbuff == NULL){
            *lpbuff = (char*)malloc(recvnum);
            if(*lpbuff == NULL)
                return -2;
        }else{
            *lpbuff = (char*)realloc(*lpbuff,recvnum);
            if(*lpbuff == NULL)
                return -2;
        }
 
        memcpy(*lpbuff+recvnum-tmpres,buff,tmpres);
    }
 
    return recvnum;
}
 
int tuobao_tcpclient_send(tuobao_tcpclient *pclient,char *buff,int size){
    int sent=0,tmpres=0;
 
    while(sent < size){
        tmpres = send(pclient->socket,buff+sent,size-sent,0);
        if(tmpres == -1){
            return -1;
        }
        sent += tmpres;
    }
    return sent;
}
 
int tuobao_tcpclient_close(tuobao_tcpclient *pclient){
    close(pclient->socket);
    pclient->connected = 0;
}
