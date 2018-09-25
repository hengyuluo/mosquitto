#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <stdlib.h>
#include <string.h>
#include "/usr/include/mysql/mysql.h"
#include <openssl/hmac.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>


#ifndef _TUOBAO_TCP_CLIENT_
#define _TUOBAO_TCP_CLIENT_
#define MAXLINE 1024
#define BUFFER_SIZE 1024


typedef struct _tuobao_tcpclient{
	int socket;
	int remote_port;
	char remote_ip[16];
	struct sockaddr_in _addr;
	int connected;
} tuobao_tcpclient;

int tuobao_tcpclient_create(tuobao_tcpclient *,const char *host, int port);
int tuobao_tcpclient_conn(tuobao_tcpclient *);
int tuobao_tcpclient_recv(tuobao_tcpclient *,char **lpbuff,int size);
int tuobao_tcpclient_send(tuobao_tcpclient *,char *buff,int size);
int tuobao_tcpclient_close(tuobao_tcpclient *);

#endif


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

int http_post(tuobao_tcpclient *pclient,char *page,char *request,char **response){
 
    char post[300],host[100],content_len[100];
    char *lpbuf,*ptmp;
    int len=0;
 
    lpbuf = NULL;
    const char *header2="User-Agent: Tuobao Http 0.1\r\nCache-Control: no-cache\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: */*\r\n";
 
    sprintf(post,"POST %s HTTP/1.0\r\n",page);
    sprintf(host,"HOST: %s:%d\r\n",pclient->remote_ip,pclient->remote_port);
    sprintf(content_len,"Content-Length: %d\r\n\r\n",strlen(request));
 
    len = strlen(post)+strlen(host)+strlen(header2)+strlen(content_len)+strlen(request)+1;
    lpbuf = (char*)malloc(len);
    if(lpbuf==NULL){
        return -1;
    }
 
    strcpy(lpbuf,post);
    strcat(lpbuf,host);
    strcat(lpbuf,header2);
    strcat(lpbuf,content_len);
    strcat(lpbuf,request);
	
	//printf("this is use      ");
	//printf(lpbuf);
 
    if(!pclient->connected){
        tuobao_tcpclient_conn(pclient);
    }
 
    if(tuobao_tcpclient_send(pclient,lpbuf,len)<0){
        return -1;
    }
    printf("this is return%s\n####",lpbuf,"\r\n");
 
    if(tuobao_tcpclient_recv(pclient,&lpbuf,0) <= 0){
		printf(lpbuf);
        if(lpbuf) free(lpbuf);
        return -2;
	}
	printf("this is return%s\n####",lpbuf,"\r\n");
 
    memset(post,0,sizeof(post));
    strncpy(post,lpbuf+9,3);
    if(atoi(post)!=200){
        if(lpbuf) free(lpbuf);
        return atoi(post);
    }
 
    ptmp = (char*)strstr(lpbuf,"\r\n\r\n");
    if(ptmp == NULL){
        free(lpbuf);
        return -3;
    }
    ptmp += 4;
 
    len = strlen(ptmp)+1;
    *response=(char*)malloc(len);
    if(*response == NULL){
        if(lpbuf) free(lpbuf);
        return -1;
    }
    memset(*response,0,len);
    memcpy(*response,ptmp,len-1);
 
    ptmp = (char*)strstr(lpbuf,"Content-Length:");
    if(ptmp != NULL){
        char *ptmp2;
        ptmp += 15;
        ptmp2 = (char*)strstr(ptmp,"\r\n");
        if(ptmp2 != NULL){
            memset(post,0,sizeof(post));
            strncpy(post,ptmp,ptmp2-ptmp);
            if(atoi(post)<len)
                (*response)[atoi(post)] = '\0';
        }
    }
 
    if(lpbuf) free(lpbuf);
 
    return 0;
}

char *base64_encode(const char* data, int data_len) 
{ 
	//int data_len = strlen(data); 
	const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="; 
	int prepare = 0; 
	int ret_len; 
	int temp = 0; 
	char *ret = NULL; 
	char *f = NULL; 
	int tmp = 0; 
	char changed[4]; 
	int i = 0; 
	ret_len = data_len / 3; 
	temp = data_len % 3; 
	if (temp > 0) 
	{ 
		ret_len += 1; 
	} 
	ret_len = ret_len*4 + 1; 
	ret = (char *)malloc(ret_len); 

	if ( ret == NULL) 
	{ 
		printf("No enough memory.\n"); 
		exit(0); 
	} 
	memset(ret, 0, ret_len); 
	f = ret; 
	while (tmp < data_len) 
	{ 
		temp = 0; 
		prepare = 0; 
		memset(changed, '\0', 4); 
		while (temp < 3) 
		{ 
			//printf("tmp = %d\n", tmp); 
			if (tmp >= data_len) 
			{ 
				break; 
			} 
			prepare = ((prepare << 8) | (data[tmp] & 0xFF)); 
			tmp++; 
			temp++; 
		} 
		prepare = (prepare<<((3-temp)*8)); 
		//printf("before for : temp = %d, prepare = %d\n", temp, prepare); 
		for (i = 0; i < 4 ;i++ ) 
		{ 
			if (temp < i) 
			{ 
				changed[i] = 0x40; 
			} 
			else 
			{ 
				changed[i] = (prepare>>((3-i)*6)) & 0x3F; 
			} 
			*f = base[changed[i]]; 
			//printf("%.2X", changed[i]); 
			f++; 
		} 
	} 
	*f = '\0'; 

	return ret; 

} 
//char *login_check(char *deviceName, char *productKey)
//{
//        MYSQL *g_conn = mysql_init(NULL);
//        MYSQL_RES *g_res = NULL;
//        MYSQL_ROW g_row;
//
//        const char *g_host_name = "localhost";
//        const char *g_user_name = "root";
//        const char *g_password = "123456";
//        const char *g_db_name = "mosquitto_test";
//        const unsigned int g_db_port = 3306;
//        const int MAX_SIZE = 1024;
//		printf("1\n");
//        //g_conn = mysql_init(NULL);
//
//        /* connect the database */
//		g_conn = mysql_real_connect(g_conn, g_host_name, g_user_name, g_password, g_db_name, g_db_port, NULL, 0);
//        if(!g_conn)
//	{
//		printf("%s", mysql_error(g_conn));
//		printf("\n");
//		return "-1";
//	}
//		printf("2:   %x\n", g_conn);
//
//		//if (mysql_real_query(g_conn,"set names utf8", strlen("set names utf8")))
//		//{
//		//	printf("333\n");
//		//	return "-1";
//		//}
//		//g_res = mysql_store_result(g_conn);
//		//mysql_free_result(g_res);
//
//		printf("3\n");
//		char *sql = (char*)malloc(sizeof(char) * MAX_SIZE);
//		memset(sql, 0, MAX_SIZE);
//       // char sql[MAX_SIZE];
//        sprintf(sql, "select deviceName, productKey, deviceSecret from user_login where deviceName = '");
//        strcat(sql, deviceName);
//        strcat(sql, "' and ");
//        strcat(sql, "productKey = '");
//        strcat(sql, productKey);
//        strcat(sql, "' ");
//	printf("%s", "query:");
//	printf("%s", sql);
//	printf("\n");
//
//        if (mysql_real_query(g_conn,sql, strlen(sql)))
//                printf("%s", "query error");
//
//        g_res = mysql_store_result(g_conn);
//
//        int iNum_rows = mysql_num_rows(g_res);
//
//
//		char* result = NULL;
//        if(iNum_rows == 0)
//        {
//                result = "0";
//        }
//        else
//        {
//                g_row = mysql_fetch_row(g_res);
//				result = (char *)malloc(sizeof(char) * strlen(g_row[2]) + 1);
//				memset(result, 0, strlen(g_row[2]) + 1);
//				memcpy(result, g_row[2], strlen(g_row[2]));
//                //char *result = g_row[2];
//        }
//
//		printf("address:  %x, %x, %x, %x, %x, %x\n", g_res, g_conn,g_host_name,  g_password, g_db_name, sql);
//
//		mysql_free_result(g_res);
//		mysql_close(g_conn);
//		free(sql);
//		sql = NULL;
//
//		return result;
//}

//char *hmacsha1(char *key, char *data)
//{
//        //// The secret key for hashing
//        //const char key[] = "012345678";
//
//        //// The data that we're going to hash
//        //char data[] = "hello world";
//
//        // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
//        // Change the length accordingly with your choosen hash engine.
//       /* unsigned char* result;
//        unsigned int len = 100;
//
//        result = (unsigned char*)malloc(sizeof(char) * len);
//
//        HMAC_CTX ctx
//        HMAC_CTX_init(&ctx);
//
//        // Using sha1 hash engine here.
//        // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
//        HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
//        HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
//        HMAC_Final(&ctx, result, &len);
//        HMAC_CTX_cleanup(&ctx);
//
//        printf("HMAC digest: ");
//
//        for (int i = 0; i != len; i++)
//                printf("%02x", (unsigned int)result[i]);
//
//        printf("\n");
//
//        return result;
//	*/
//	printf("1\n");
//    unsigned char digest[EVP_MAX_MD_SIZE] = {'\0'};
//	printf("2\n");
//    unsigned int digest_len = 0;
//	printf("3\n");
//	printf("key:%s\n", key);
//	printf("data:%s\n", data);
//    // Using sha1 hash engine here.
//    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
//    HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), digest, &digest_len);
//	printf("4\n");
//    printf("%s, len %u\n", digest, digest_len);
//
//    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
//    // Change the length accordingly with your choosen hash engine
//    char *mdString = (char*)malloc(sizeof(char) * 100);
//    memset(mdString, 0, 100);
//	printf("5\n");
//    for(int i = 0; i < 20; i++)
//         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
//
//   // printf("HMAC digest: %s\n", mdString);
//
//    return mdString;
//}


int mosquitto_auth_plugin_version(void)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *auth_opts, int auth_opt_count, bool reload)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access, const struct mosquitto *client, const struct mosquitto_acl_msg *msg)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);
	//printf("I get a clientID:%s\n", mosquitto_client_id(client));
	tuobao_tcpclient tcpClient;
	const char *username = mosquitto_client_username(client);
	char *response = NULL;
	char *c_access = (char*)malloc(sizeof(char) * 2);
	memset(c_access, 0, 2);
	switch(access){
	case 1:{
		strcpy(c_access,"1");
		break;
		   }
	case 2:{
		strcpy(c_access,"2");
		break;
		   }
	case 4:{
		strcpy(c_access,"4");
		break;
		   }
	default:{
		strcpy(c_access,"9");
		break;
			}
	}
	char *base64Username = (char*)malloc(sizeof(char) * 300);
	memset(base64Username, 0, 300);
	base64Username = base64_encode(username, strlen(username));
	tuobao_tcpclient_create(&tcpClient,"192.168.81.245",9090);  //TODO
	char *message = (char*)malloc(sizeof(char) * 300);
	memset(message, 0, 300);
	strcat(message, "username=");
	strcat(message, base64Username);
	strcat(message, "&topicName=");
	strcat(message, msg->topic);
	strcat(message, "&access=");
	strcat(message, c_access);
	http_post(&tcpClient,"http://192.168.81.245:9090//a", message, &response);
	tuobao_tcpclient_close(&tcpClient);
	if(base64Username){
		free(base64Username);
		base64Username = NULL;
	}
	if(c_access)
	{
		free(c_access);
		c_access = NULL;
	}
	if(message)
	{
		free(message);
		message = NULL;
	}
	if(!strcmp(response, "1"))
	{
		if(response){
			free(response);
			response = NULL;
		}
		return MOSQ_ERR_SUCCESS;
	}
	else
	{
		if(response){
			free(response);
			response = NULL;
		}
		return MOSQ_ERR_ACL_DENIED;
	}
	//if(username && !strcmp(username, "readonly") && access == MOSQ_ACL_READ){
	//	return MOSQ_ERR_SUCCESS;
	//}else if(username && !strcmp(username, "readonly") && access == MOSQ_ACL_SUBSCRIBE &&!strchr(msg->topic, '#') && !strchr(msg->topic, '+')) {
	//	return MOSQ_ERR_SUCCESS;
	//}else{
	//	return MOSQ_ERR_ACL_DENIED;
	//}
}
#include "mosquitto_internal.h" 
int mosquitto_auth_unpwd_check(void *user_data, const struct mosquitto *client, const char *username, const char *password)
{
////	struct mosquitto *ptest = (struct mosquitto *)client;
////	printf("=============================user_data=%s\n",(char*)user_data);	
//	
//	/*	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);
//
//	if(!strcmp(username, "test-username") && password && !strcmp(password, "cnwTICONIURW")){
//		printf("*************1***********");
//		return MOSQ_ERR_SUCCESS;
//	}else if(!strcmp(username, "readonly")){
//		printf("*************2***********");
//
//		return MOSQ_ERR_SUCCESS;
//	}else if(!strcmp(username, "test-username@v2")){
//		printf("*************3***********");
//
//
//		return MOSQ_ERR_PLUGIN_DEFER;
//	}else{
//		printf("*************4***********");
//
//
//		return MOSQ_ERR_AUTH;
//	}
//*/
////	char *x = "123456";
////	printf("123123123123");
////	char p[100] = {0};
////	printf("p1 = %s", p);
////	printf("\n");
////	while(*p){
////		printf(*p);
////		p = p+1;
////	};
////	memcpy(p, x, 99);
////	printf("45645645645645");
////	printf("\n");
////	struct userdata *ud = (struct userdata *)user_data;
////	struct cliententry *e;
////	HASH_FIND(hh, ud->clients, &client, sizeof(void *), e);
////	const int *a = (int*) client;
////	printf("p2 =%s", p);
//
//	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);
////	printf("clientiddddd:");
////	printf("%s",  (char*)client->id);
//	printf("\n");
//
//	printf("username:");
//        printf("%s", username);
//	printf("\n");
//
//	printf("password:");
//        printf("%s", password);
//	printf("\n");
//	char *split = (char*)malloc(sizeof(char) * 2);
//	//printf("333333333333333");
//	memset(split, 0, 2);
//	//printf("222222222222222222");
//	memcpy(split, "&", 2);
//	//printf("11111111111111111111111111111111111111111");
////	char *split = "&";
////	printf("ttttttttttttttttttttt%s\ntttttttttttttttttttt", split);
//	char *tempUsername = (char*)malloc(sizeof(char) * 100);
//	memset(tempUsername, 0, 100);
//	//char tempUsername[100];
//	memcpy(tempUsername, username, strlen(username));
//	printf("tempUsername:");
//	printf("%s",tempUsername);
//	printf("\n");
//
////	char tempUsername[20] = "aaa&bbb";
////	char *split = "&";
////	char *deviceName = strtok(tempUsername, split);
////	printf("%s\n", "123");
////	char *productKey = strtok(NULL, split);
////	printf("%s\n", "456");
////	const char tempUsername[100] = "testName&testKey";
////	char *deviceName = (char*)melloc(sizeof(char) * 
//	char *deviceName = (char*)malloc(sizeof(char) * 100);
//	memset(deviceName, 0, 100);
//	char *productKey = (char*)malloc(sizeof(char) * 100);
//	memset(productKey, 0, 100);
//	memcpy(deviceName, strtok(tempUsername, split), 100);
//	memcpy(productKey, strtok(NULL,split), 100);
//
//	//char *productSecret = (char*)malloc((sizeof(char) * 100));
//	//memset(productSecret, 0, sizeof(char) * 100);
//	//printf("before_productSecret:%s\n", productSecret);
//	printf("deviceName:");
//    printf("%s", deviceName);
//	printf("\n");
//	printf("productKey:%s\n", productKey);
//
//	char *productSecret = login_check(deviceName, productKey);
//	printf("search done");
//	printf("\n");
//	printf("productSecret:%s\n", productSecret);
//
///*	if(strcmp(productSecret, "0") == 0)
//	{
//		printf("%s", "user does not exist.");
//		return MOSQ_ERR_AUTH;
//	}
//
//	else if(strcmp(productSecret, "-1") == 0)
//	{
//		printf("%s", "mysql error!");
//		return MOSQ_ERR_AUTH;
//	}*/
//	memcpy(split, "|", 2);
////	const char *clientID = "123123|securemode=3,sighmethod=hmacsha1,timestamp=100|";
//      //  const char *clientID = mosquitto_client_id(client);
////        char *clientID = (char*)user_data;
////	printf("client id:");
////	printf("%s\n", clientID);
//
//	printf("user_data:%s\n", user_data);
//	printf("length:%d\n", strlen((char*)user_data));
//	int length = sizeof(char) * strlen((char*)user_data);
//	printf("user_data address%x\n", user_data);
//
//	char *tempClientID = (char *)malloc(length + 1);
//	printf("user_data address:%x\n", user_data);
//	printf("tempClientID1 address:%x\n",tempClientID );
//	printf("tempClientID1:%s\n", tempClientID);
//
//
//	memset(tempClientID, 0, length + 1);
//
//	printf("user_data address%x", user_data);
//	printf("after user_data:%s\n", user_data);
//	printf("tempClientID2:%s\n", tempClientID);
//	strncpy(tempClientID, (char*)user_data, length);
//	printf("tempClientID:%s\n", tempClientID);
//	printf("tempClientIDLength%d,%d\n", strlen(tempClientID),sizeof(tempClientID));
//	char *ID = (char*)malloc(sizeof(char) * 100);
//	memset(ID, 0, 100);
//	memcpy(ID, strtok(tempClientID, split), 100);
//	//char *ID = strtok(tempClientID, split);
//	printf("ID:%s\n",ID);
//	memcpy(split, ",", 2);
//	char *secureMode = (char*)malloc(sizeof(char) * 100);
//	memset(secureMode, 0, 100);
//	memcpy(secureMode, strtok(NULL, split), 100);
//	//char *secureMode = strtok(NULL, split);
//	printf("secureMode:%s\n",secureMode);
//	char *sighMethod = (char*)malloc(sizeof(char) * 100);
//	memcpy(sighMethod, strtok(NULL, split), 100);
//	//char *sighMethod = strtok(NULL, split);
//	printf("sighMethod:%s\n",sighMethod);
//
//	memcpy(split, "|", 2);
//	char *timeStamp = (char*)malloc(sizeof(char) * 100);
//	memset(timeStamp, 0, 100);
//	memcpy(timeStamp, strtok(NULL, split), 100);
//	//char *timeStamp = strtok(NULL, split);
//	printf("timeStamp:%s\n",timeStamp);
//
//	memcpy(split, "=", 1);
//	char *temp = (char *)malloc(sizeof(char) * 100);
//	memset(temp, 0, 100);
//	memcpy(temp, strtok(secureMode, split), 100);
//	//temp = strtok(secureMode, split);
//	char *realSecureMode = (char*)malloc(sizeof(char) * 100);
//	memcpy(realSecureMode, strtok(NULL, ""), 100);
//	//char *realSecureMode = strtok(NULL, "");
//	printf("realSecureMode:%s\n",realSecureMode);
//
//	/*temp = strtok(deviceName, split);
//	char *realDeviceName = strtok(NULL, "");
//	printf("realDeviceName:%s\n",realDeviceName);
//
//	temp = strtok(productKey, split);
//	char *realProductKey = strtok(NULL, "");
//	printf("realProductKey:%s\n",realProductKey);
//*/
//	memcpy(temp, strtok(timeStamp, split), 100);
//	//temp = strtok(timeStamp, split);
//	char *realTimeStamp = (char*)malloc(sizeof(char) * 100);
//	memset(realTimeStamp, 0, 100);
//	memcpy(realTimeStamp, strtok(NULL, ""), 100);
//	//char *realTimeStamp = strtok(NULL, "");
//	printf("realTimeStamp:%s\n",realTimeStamp);
//
//	memcpy(temp, strtok(sighMethod, split), 100);
//	//temp = strtok(sighMethod, split);
//	char *realSignMethod = (char*)malloc(sizeof(char) * 100);
//	memset(realSignMethod, 0, 100);
//	memcpy(realSignMethod, strtok(NULL, ""), 100);
//	//char *realSignMethod = strtok(NULL, "");
//	printf("realSIghMEthod:%s\n",realSignMethod);
//
//
//	char *combination = (char*)malloc(sizeof(char) * 1024);
////	combination = "clientid";
////	printf("9999999999999999999999%s\n",combination);	
//	memset(combination, 0, sizeof(char) * 1024);
//	strcat(combination, "clientid");
//	strcat(combination, ID);
//	strcat(combination, "deviceName");
//	strcat(combination, deviceName);
//	strcat(combination, "productKey");
//	strcat(combination, productKey);
//	strcat(combination, "timestamp");
//	strcat(combination, realTimeStamp);
//	printf("combine:");
//    printf("%s", combination);
//    printf("\n");
//
//	free(split);
//	split = NULL;
//	free(deviceName);
//	free(productKey);
//
//	deviceName = NULL;
//	productKey = NULL;
//
////	free(clientID);
//
//	//if(user_data)
//	//{
//	//	free(user_data);
//	//	user_data = NULL;
//	//}
//
//	if(tempClientID != NULL)
//	{	
//		free(tempClientID);
//		tempClientID = NULL;
//	}
//
//
//	free(ID);
//	free(secureMode);
//	free(sighMethod);
//	free(timeStamp);
//	free(temp);
//	free(realSecureMode);
//	free(realTimeStamp);
//	free(realSignMethod);
//	ID = NULL;
//	secureMode = NULL;
//	sighMethod = NULL;
//	timeStamp = NULL;
//	temp = NULL;
//	realSecureMode = NULL;
//	realTimeStamp = NULL;
//	realSignMethod = NULL;
//	char *hashResult = hmacsha1(productSecret, combination);
//	free(productSecret);
//	productSecret = NULL;
//	printf("hash:%s\n", hashResult);
///*	if(strcmp(realSignMethod, "hmacsha1") == 0)
//	{
//		char *Hash_result = hmacsha1(combination, productSecret);
//		if(strcmp(Hash_result, password) == 0)
//		{
//			printf("%s", "welcome");
//			return MOSQ_ERR_SUCCESS;
//		}
//		else
//		{
//			printf("%s", "password incorrect");
//			return MOSQ_ERR_AUTH;
//		}
//	}
//	else
//	{
//		printf("%s", "no such sighMethod!");
//		return MOSQ_ERR_AUTH;
//		}*/
//	if(strncmp(hashResult, password, strlen(combination)) == 0){
//		printf("welcome\n");
//		free(combination);
//		combination = NULL;
//		printf("success\n");
//		free(hashResult);
//		hashResult = NULL;
//		return MOSQ_ERR_SUCCESS;
//	}
//	else{
//		printf("password error\n");
//		free(combination);
//		combination = NULL;
//		                free(hashResult);
//                hashResult = NULL;
//
//		return MOSQ_ERR_AUTH;
//	}
// 
	//printf("I get a clientID:%s\n", mosquitto_client_id(client));

	char *base64Username = (char*)malloc(sizeof(char) * 300);
	memset(base64Username, 0, 300);
	base64Username = base64_encode(username, strlen(username));
    tuobao_tcpclient tcpClient;
 
    char *response = NULL;
    printf("start combling\n"); 
    tuobao_tcpclient_create(&tcpClient,"192.168.81.245",9090);  //TODO
	char *msg = (char*)malloc(sizeof(char) * 300);
	memset(msg, 0, 300);
	strcat(msg,"username=");
	strcat(msg, base64Username);
	strcat(msg, "&");
	strcat(msg, "password=");
	strcat(msg, password);
	strcat(msg, "&");
	strcat(msg, "clientID=");
	strcat(msg, mosquitto_client_id(client));

	printf("msg:%s\n", msg);
	//http_post(&client,"http://192.168.81.185:6089/test","md5=195731",&response);
	printf(response);
    http_post(&tcpClient,"http://192.168.81.245:9090//q", msg, &response);  //TODO	//http_post_file(&client,"http://www.example.com","./test",&response);
	tuobao_tcpclient_close(&tcpClient);
	free(msg);
	msg = NULL;
	if(base64Username){
		free(base64Username);
		base64Username = NULL;
	}
	//printf("this is response");
 //   printf(":\n%d:%s\n",strlen(response),response);
	if(!strcmp(response, "0")){
		if(response){
			free(response);
			response = NULL;
		}
		
		return MOSQ_ERR_SUCCESS;
	}
	else{
		if(response){
			free(response);
			response = NULL;
		}
		return MOSQ_ERR_UNKNOWN;
	}
}

int mosquitto_auth_psk_key_get(void *user_data, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_AUTH;
}

