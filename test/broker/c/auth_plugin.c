#include <stdio.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <stdlib.h>
#include <string.h>
#include "/usr/include/mysql/mysql.h"
#include <openssl/hmac.h>
//#include "/mosquitto-cluster/mosquitto-auth-plug/hash.h"
//#include "/mosquitto-cluster/mosquitto-auth-plug/backends.h"
//#include "/mosquitto-cluster/mosquitto-auth-plug/cache.h"
//#include "/mosquitto-cluster/lib/cpp/mosquittopp.h"
char *login_check(char *deviceName, char *productKey)
{
        MYSQL *g_conn = mysql_init(NULL);
        MYSQL_RES *g_res;
        MYSQL_ROW g_row;

        const char *g_host_name = "localhost";
        const char *g_user_name = "root";
        const char *g_password = "123456";
        const char *g_db_name = "mosquitto_test";
        const unsigned int g_db_port = 3306;
        const int MAX_SIZE = 1024;

        //g_conn = mysql_init(NULL);

        /* connect the database */
        if(!mysql_real_connect(g_conn, g_host_name, g_user_name, g_password, g_db_name, g_db_port, NULL, 0))
	{
		printf("%s", mysql_error(g_conn));
		printf("\n");
		return "-1";
	}


        if (mysql_real_query(g_conn,"set names utf8", strlen("set names utf8")))
                return "-1";

//        if (init_mysql());
//        print_mysql_error(NULL);

        char sql[MAX_SIZE];
        sprintf(sql, "select deviceName, productKey, deviceSecret from user_login where deviceName = '");
        strcat(sql, deviceName);
        strcat(sql, "' and ");
        strcat(sql, "productKey = '");
        strcat(sql, productKey);
        strcat(sql, "' ");
	
	printf("%s", "query:");
	printf("%s", sql);
	printf("\n");

        if (mysql_real_query(g_conn,sql, strlen(sql)))
                printf("%s", "query error");

        g_res = mysql_store_result(g_conn);

        int iNum_rows = mysql_num_rows(g_res);
 if(iNum_rows == 0)
        {
                mysql_free_result(g_res);
                mysql_close(g_conn);
                return "0";
        }
        else
        {
                g_row = mysql_fetch_row(g_res);
                char *result = g_row[2];
                mysql_free_result(g_res);
                mysql_close(g_conn);
                return result;
        }
	free(g_host_name);
    free(g_user_name);
    free(g_password);
    free(g_db_name);
	g_host_name = NULL;
	g_user_name = NULL;
	g_password = NULL;
	g_db_name = NULL;
}

char *hmacsha1(char *key, char *data)
{
        //// The secret key for hashing
        //const char key[] = "012345678";

        //// The data that we're going to hash
        //char data[] = "hello world";

        // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
        // Change the length accordingly with your choosen hash engine.
/*        unsigned char* result;
        unsigned int len = 100;

        result = (unsigned char*)malloc(sizeof(char) * len);

        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);

        // Using sha1 hash engine here.
        // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
        HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
        HMAC_Update(&ctx, (unsigned char*)&data, strlen(data));
        HMAC_Final(&ctx, result, &len);
        HMAC_CTX_cleanup(&ctx);

        printf("HMAC digest: ");

        for (int i = 0; i != len; i++)
                printf("%02x", (unsigned int)result[i]);

        printf("\n");

        return result;
	*/
	return data;
}


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

	const char *username = mosquitto_client_username(client);

	if(username && !strcmp(username, "readonly") && access == MOSQ_ACL_READ){
		return MOSQ_ERR_SUCCESS;
	}else if(username && !strcmp(username, "readonly") && access == MOSQ_ACL_SUBSCRIBE &&!strchr(msg->topic, '#') && !strchr(msg->topic, '+')) {
		return MOSQ_ERR_SUCCESS;
	}else{
		return MOSQ_ERR_ACL_DENIED;
	}
}
#include "mosquitto_internal.h" 
int mosquitto_auth_unpwd_check(void *user_data, const struct mosquitto *client, const char *username, const char *password)
{
	printf("errorrrrrrrrrrrrrrr\n");
	return MOSQ_ERR_AUTH;
//	struct mosquitto *ptest = (struct mosquitto *)client;
//	printf("=============================user_data=%s\n",(char*)user_data);	
	
	/*	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	if(!strcmp(username, "test-username") && password && !strcmp(password, "cnwTICONIURW")){
		printf("*************1***********");
		return MOSQ_ERR_SUCCESS;
	}else if(!strcmp(username, "readonly")){
		printf("*************2***********");

		return MOSQ_ERR_SUCCESS;
	}else if(!strcmp(username, "test-username@v2")){
		printf("*************3***********");


		return MOSQ_ERR_PLUGIN_DEFER;
	}else{
		printf("*************4***********");


		return MOSQ_ERR_AUTH;
	}
*/
//	char *x = "123456";
//	printf("123123123123");
//	char p[100] = {0};
//	printf("p1 = %s", p);
//	printf("\n");
//	while(*p){
//		printf(*p);
//		p = p+1;
//	};
//	memcpy(p, x, 99);
//	printf("45645645645645");
//	printf("\n");
//	struct userdata *ud = (struct userdata *)user_data;
//	struct cliententry *e;
//	HASH_FIND(hh, ud->clients, &client, sizeof(void *), e);
//	const int *a = (int*) client;
//	printf("p2 =%s", p);

	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);
//	printf("clientiddddd:");
//	printf("%s",  (char*)client->id);
	printf("\n");

	printf("username:");
        printf("%s", username);
	printf("\n");

	printf("password:");
        printf("%s", password);
	printf("\n");
	char *split = (char*)malloc(sizeof(char) * 2);
	printf("333333333333333");
	memset(split, 0, 2);
	printf("222222222222222222");
	memcpy(split, "&", 2);
	printf("11111111111111111111111111111111111111111");
//	char *split = "&";
//	printf("ttttttttttttttttttttt%s\ntttttttttttttttttttt", split);
	char tempUsername[100];
	strcpy(tempUsername, username);
	printf("temoUsnm:");
	printf("%s",tempUsername);
	printf("\n");

//	char tempUsername[20] = "aaa&bbb";
//	char *split = "&";
//	char *deviceName = strtok(tempUsername, split);
//	printf("%s\n", "123");
//	char *productKey = strtok(NULL, split);
//	printf("%s\n", "456");
//	const char tempUsername[100] = "testName&testKey";
//	char *deviceName = (char*)melloc(sizeof(char) * 
	char *deviceName = strtok(tempUsername, split);
//	char *deviceName = strtok("testName&testKey","&");
//	printf("123");
	
	char *productKey = strtok(NULL,split);
//	printf("456");
	char *productSecret = (char*)malloc((sizeof(char) * 1024));
	memset(productSecret, 0, sizeof(char) * 1024);
	printf("before_productSecret:%s\n", productSecret);
	printf("deviceName:");
    printf("%s", deviceName);
	printf("\n");

	memcpy(productSecret, login_check(deviceName, productKey), strlen(login_check(deviceName, productKey)));
	printf("search done");
	printf("\n");
	printf("productKey:");
        printf("%s", productKey);
        printf("\n");
/*	if(strcmp(productSecret, "0") == 0)
	{
		printf("%s", "user does not exist.");
		return MOSQ_ERR_AUTH;
	}

	else if(strcmp(productSecret, "-1") == 0)
	{
		printf("%s", "mysql error!");
		return MOSQ_ERR_AUTH;
	}*/
	memcpy(split, "|", 2);
//	const char *clientID = "123123|securemode=3,sighmethod=hmacsha1,timestamp=100|";
      //  const char *clientID = mosquitto_client_id(client);
//        char *clientID = (char*)user_data;
//	printf("client id:");
//	printf("%s\n", clientID);

	printf("user_data:%s\n", user_data);
	printf("length:%d\n", strlen((char*)user_data));
	int length = sizeof(char) * strlen((char*)user_data);
	printf("user_data address%x\n", user_data);

	char *tempClientID = (char *)malloc(length + 1);
	char *freeTempClientID = tempClientID;
	printf("user_data address:%x\n", user_data);
	printf("tempClientID1 address:%x\n",tempClientID );
	printf("tempClientID1:%s\n", tempClientID);


	memset(tempClientID, 0, length + 1);

	printf("user_data address%x", user_data);
	printf("after user_data:%s\n", user_data);
	printf("tempClientID2:%s\n", tempClientID);
	memmove(tempClientID, user_data, length);
	printf("tempClientID:%s\n", tempClientID);
	printf("tempClientIDLength%d,%d\n", strlen(tempClientID),sizeof(tempClientID));
	char *ID = strtok(tempClientID, split);
	printf("ID:%s\n",ID);
	memcpy(split, ",", 2);
	char *secureMode = strtok(NULL, split);
	printf("secureMode:%s\n",secureMode);

	char *sighMethod = strtok(NULL, split);
	printf("sighMethod:%s\n",sighMethod);

	memcpy(split, "|", 2);
	char *timeStamp = strtok(NULL, split);
	printf("timeStamp:%s\n",timeStamp);

	memcpy(split, "=", 1);
	char *temp = (char *)malloc(sizeof(char) * 100);
	temp = strtok(secureMode, split);
	char *realSecureMode = strtok(NULL, "");
	printf("realSecureMode:%s\n",realSecureMode);

	/*temp = strtok(deviceName, split);
	char *realDeviceName = strtok(NULL, "");
	printf("realDeviceName:%s\n",realDeviceName);

	temp = strtok(productKey, split);
	char *realProductKey = strtok(NULL, "");
	printf("realProductKey:%s\n",realProductKey);
*/
	temp = strtok(timeStamp, split);
	char *realTimeStamp = strtok(NULL, "");
	printf("realTimeStamp:%s\n",realTimeStamp);

	temp = strtok(sighMethod, split);
	char *realSignMethod = strtok(NULL, "");
	printf("realSIghMEthod:%s\n",realSignMethod);


	char *combination = (char*)malloc(sizeof(char) * 1024);
//	combination = "clientid";
//	printf("9999999999999999999999%s\n",combination);	
	memset(combination, 0, sizeof(char) * 1024);
	strcat(combination, "clientid");
	strcat(combination, ID);
	strcat(combination, "deviceName");
	strcat(combination, deviceName);
	strcat(combination, "productKey");
	strcat(combination, productKey);
	strcat(combination, "timestamp");
	strcat(combination, realTimeStamp);
	printf("combine:");
    printf("%s", combination);
    printf("\n");

	free(split);
	split = NULL;
//	free(deviceName);
//	free(productKey);
	free(productSecret);
	productSecret = NULL;
//	free(clientID);

	//if(user_data)
	//{
	//	free(user_data);
	//	user_data = NULL;
	//}

	if(tempClientID != NULL)
	{	
		free(tempClientID);
		tempClientID = NULL;
	}


//	free(ID);
//	free(secureMode);
//	free(sighMethod);
//	free(timeStamp);
//	free(temp);
//	free(realSecureMode);
//	free(realTimeStamp);
//	free(realSignMethod);
	



/*	if(strcmp(realSignMethod, "hmacsha1") == 0)
	{
		char *Hash_result = hmacsha1(combination, productSecret);
		if(strcmp(Hash_result, password) == 0)
		{
			printf("%s", "welcome");
			return MOSQ_ERR_SUCCESS;
		}
		else
		{
			printf("%s", "password incorrect");
			return MOSQ_ERR_AUTH;
		}
	}
	else
	{
		printf("%s", "no such sighMethod!");
		return MOSQ_ERR_AUTH;
		}*/
	if(strcmp(combination, password) == 0){
		printf("welcome\n");
		free(combination);
		combination = NULL;

		return MOSQ_ERR_SUCCESS;
	}
	else{
		printf("password error\n");
		free(combination);
		combination = NULL;

		return MOSQ_ERR_AUTH;
	}
}

int mosquitto_auth_psk_key_get(void *user_data, const struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len)
{
	printf("##################%s:%s:%d\n",__FILE__, __FUNCTION__, __LINE__);

	return MOSQ_ERR_AUTH;
}

