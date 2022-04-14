#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "file.h"

#define USER_TOP_DIR "/home/lwy/sendfile/"

#define SERVERPORT_REGISTER 8080
#define SERVERPORT_SERVICE 8081
#define PORT_FILE 8082
#define SERVERADDR INADDR_ANY

#define LISTEN_MAX 10
#define REGISTER_MAX 10
#define ONLINE_MAX 100

#define TYPE_SIZE 32
#define USERNAME_MAXSIZE 16
#define PASSWD_MAXSIZE 16

#define LENGTH_IN_MESSAGE_ZERO_NUM 2

#define REASON_USERNAME_ERROR "username is wrong"
#define REASON_TYPE_ERROR "type is wrong"
#define REASON_LENGTH_ERROR "length of message is wrong"
#define REASON_PASSWD_CIPHER_ERROR "cipher of passwd hash is wrong"
#define REASON_PASSWD_ERROR "passwd is wrong"
#define REASON_SUBPATH_ERROR "subpath is wrong"
#define REASON_DIRNAME_ERROR "dirname is wrong"
#define REASON_FILENAME_ERROR "filename is wrong"

#define REIGISTER_RESPONSE "register_response"
#define LOGIN_RESPONSE "login_response"

#define SUBPATH_MAX 64
#define FILENAME_MAX 32
#define BUFFER_DATASIZE_MAX 1024

#define FILE_SERVICE_MAX 8
#define FILE_PORT_server 100

int clientfd_online[ONLINE_MAX];
int fileport[FILE_PORT_server];

#define MAX_EVENTS 100
int timeout = 3000;
int epollfd; // no mutex
struct epoll_event eventlist[MAX_EVENTS] = {0};

typedef struct sendfile_param{
	int fd;
	int sockfd;
	struct sendfile_param* next;
} fd_sockfd;

fd_sockfd fd_root; // no mutex
fd_sockfd* fd_rear; // no mutex

typedef struct username_key{
	char username[USERNAME_MAXSIZE];
	int sockfd;
	uint8_t key[BIG8W_BYTESIZE];
	uint8_t file_upload;
	uint8_t file_download;
	uint8_t vip;
	struct username_key* next;
} user_session;

user_session root; // no mutex
user_session* rear; // no mutex

int registerfd, sevicefd, sendfile_listenfd;

void Service(struct epoll_event event, user_session *us);

char NormalCheck(char* buffer, char* username, char* type, char* type_response, int sockfd)
{
	int length;
	struct timeb timenow;

	// check length
	if ((GetWord(buffer, "length", type) == 0) || (LenStrToInt(type) != strlen(buffer))) {
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
				type_response, username, REASON_LENGTH_ERROR, timenow.time * 1000 + timenow.millitm);
    goto send;
	}

	// check type
    memset(type, 0x00, LENGTH_IN_MESSAGE_ZERO_NUM);
    if (GetWord(buffer, "type", type) == 0 ) {
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
				type_response, username, REASON_TYPE_ERROR, timenow.time * 1000 + timenow.millitm);
    goto send;
	}

	// check length of username
    if (((GetWord(buffer, "username", username)) == 0) || (strlen(username) > USERNAME_MAXSIZE)) {
		ftime(&timenow);
		username[USERNAME_MAXSIZE - 1] = 0x00;
		username[USERNAME_MAXSIZE - 2] = '*';

		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
				type_response, username, REASON_USERNAME_ERROR, timenow.time * 1000 + timenow.millitm);
    goto send;
	}

	return;

	send:
    {
    length = strlen(buffer);
	InsertLength(buffer, length);
    senddata(sockfd, buffer, strlen(buffer));
	printf("send data in NormalCheck:\n%s\nlength:%d\n", buffer, length);
	// close(sockfd);
	// pthread_exit(0);
    }
}

uint8_t InFilePort(int port)
{
	int i = 0;
	for(; i < FILE_PORT_server; i++){
		if (port == fileport[i])
			return 1;
	}
	return 0;
}

void Accept(int sevicefd)
{
	int sockfd;

	struct sockaddr_in fromaddr;
	socklen_t addrlen = sizeof(fromaddr);
	bzero(&fromaddr, addrlen);
	
	if ((sockfd = accept(sevicefd, (struct sockaddr*)&fromaddr, &addrlen)) == -1) {
		perror("accept socket failed in main.\n");
		return -1;
	}

	struct epoll_event event;
	event.events = EPOLLIN|EPOLLET;
	event.data.fd = sockfd;
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &event) < 0){
		perror("epoll error.\n");
	}

}

void ServerRegisterService(void *listenfd)
{
	int registerfd = *(int*)listenfd;

	char buffer[BUFFER_DATASIZE_MAX] = { 0 };
	char type[TYPE_SIZE] = { 0 };
	char username[USERNAME_MAXSIZE] = { 0 };
	char passwd_cipher[160] = { 0 };
	uint8_t hashvalue[SM3OUT_32BYTES] = {0};
	uint8_t secretkey_uint8t[SM3OUT_32BYTES] = {0};

	char ciphertext[64] = {0};
	char challenge[64] = {0};
	big8w secretkey, r;
	G1point pubkey;

	int length;

	struct sockaddr_in fromaddr;
	socklen_t addrlen = sizeof(fromaddr);
	bzero(&fromaddr, addrlen);

	int sockfd;
	if ((sockfd = accept(registerfd, (struct sockaddr*)&fromaddr, &addrlen)) == -1) {
		perror("accept socket failed in main.\n");
		return -1;
	}

	recvdata(sockfd, buffer, BUFFER_DATASIZE_MAX - 1);

	// printf("register data in server:\n%s\n", buffer);

	struct timeb timenow;

    NormalCheck(buffer, username, type, REIGISTER_RESPONSE, sockfd);

	if (strcmp(type, "register") != 0){
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						REIGISTER_RESPONSE, username, REASON_TYPE_ERROR, timenow.time * 1000 + timenow.millitm);
	goto send;
	}

	// get hash(passwd)
	if((GetWord(buffer, (char*)"passwd_cipher", passwd_cipher)) == 0){
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						REIGISTER_RESPONSE, username, REASON_PASSWD_CIPHER_ERROR, timenow.time * 1000 + timenow.millitm);
	goto send;
	}
	else{// register success, send ciphertext = (hash(passwd)) ^ secretkey, challenge

		// get secret key of user
		ProduceSecretKey(username, strlen(username), &secretkey, &pubkey);

		// get hash(passwd)
		EccDec_SM2Mode(passwd_cipher, passwd_cipher + 88, k1, (char*)hashvalue, SM3OUT_32BYTES);

		// get ciphertext
		length = 0;
		for(; length < SM3OUT_32BYTES; length++)
			secretkey_uint8t[length] ^= hashvalue[length];
		Base64Encode(secretkey_uint8t, BIG8W_BYTESIZE, ciphertext);
		
		// get challenge
		r = RandomNumGenerate();
		Big8wIntou8string(&r, secretkey_uint8t, 0);
		Base64Encode(secretkey_uint8t, BIG8W_BYTESIZE, challenge);

		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"success\",\"ciphertext\":\"%s\",\"challenge\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						REIGISTER_RESPONSE, username, ciphertext, challenge, timenow.time * 1000 + timenow.millitm);

		AddUser(username, hashvalue, challenge);
		
		goto send;
	}

	send:
    {
    length = strlen(buffer);
	InsertLength(buffer, length);
    senddata(sockfd, buffer, strlen(buffer));
	// printf("send data in ServerRegisterService:\n%s\nlength:%d\n", buffer, length);
	close(sockfd);
	pthread_exit(0);
    }

	close(sockfd);
    pthread_exit(0);
}

void ServerLoginService(int sockfd, char* buffer, user_session* us)
{
	char username[USERNAME_MAXSIZE] = { 0 };
	char type[TYPE_SIZE] = { 0 };

	char passwd_cipher[256] = {0};

	uint8_t hashvalue[BIG8W_BYTESIZE] = {0};
	uint8_t hashvalue_cmp[BIG8W_BYTESIZE] = {0};
	uint8_t challenge[BIG8W_BYTESIZE] = {0};

	int length;

	struct timeb timenow;

	NormalCheck(buffer, username, type, LOGIN_RESPONSE, sockfd);

	// check type
	if (strcmp(type, "login") != 0){
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						LOGIN_RESPONSE, username, REASON_TYPE_ERROR, timenow.time * 1000 + timenow.millitm);
	goto send;
	}

	// get hash(passwd)
	if((GetWord(buffer, (char*)"passwd_cipher", passwd_cipher)) == 0){
		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						LOGIN_RESPONSE, username, REASON_PASSWD_CIPHER_ERROR, timenow.time * 1000 + timenow.millitm);
	goto send;
	}else{

		GetHashvalue(username, hashvalue, challenge);

		EccDec_SM2Mode(passwd_cipher, passwd_cipher + 88, k1, (char*)hashvalue_cmp, SM3OUT_32BYTES);

		// check passwd
		for(int i = 0; i < BIG8W_BYTESIZE; i++){
			if (hashvalue[i] != (hashvalue_cmp[i] ^ challenge[i])){
				perror("user passwd error.\n");
				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
								LOGIN_RESPONSE, username, REASON_PASSWD_ERROR, timenow.time * 1000 + timenow.millitm);
				goto send;
			}
		}

		// login success. refresh challenge
		big8w r;
		r = RandomNumGenerate();
		uint8_t challenge[BIG8W_BYTESIZE] = {0};
		char challenge_encoded[BIG8W_BYTESIZE + (BIG8W_BYTESIZE >> 1)] = {0};
		char setkey_encoded[BIG8W_BYTESIZE + (BIG8W_BYTESIZE >> 1)] = {0};

		Big8wIntou8string(&r, challenge, 0);
		Base64Encode(challenge, BIG8W_BYTESIZE, challenge_encoded);

		r = RandomNumGenerate();
		memset(challenge, 0x00, BIG8W_BYTESIZE);
		Big8wIntou8string(&r, challenge, 0);
		Base64Encode(challenge, BIG8W_BYTESIZE, setkey_encoded);

		for(int i = 0; i < BIG8W_BYTESIZE; i++)
			us->key[i] = hashvalue[i] ^ challenge[i];

		us->sockfd = sockfd;
		memset(us->username, 0x00, USERNAME_MAXSIZE);
		strcpy(us->username, username);

		// printf("us.name:%s\n", us->username);
		
		us->file_download = 0;
		us->file_upload = 0;
		us->vip = 0;
		us->next = NULL;

		rear->next = us;
		rear = us;

		ftime(&timenow);
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
		sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"state\":\"success\",\"setkey\":\"%s\",\"challenge\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
						LOGIN_RESPONSE, username, setkey_encoded, challenge_encoded, timenow.time * 1000 + timenow.millitm);
		goto send;
	}

	send:
    {
    length = strlen(buffer);
	InsertLength(buffer, length);
    senddata(sockfd, buffer, length);
	// printf("send data in ServerLoginService:\n%s\nlength:%d\n", buffer, length);
	// close(sockfd);
	// pthread_exit(0);
    }
}

int ServerService()
{
	int epoll_wait_ret;
	int i;
	
	registerfd = CreateListenSockfd(SERVERPORT_REGISTER);
	sevicefd = CreateListenSockfd(SERVERPORT_SERVICE);
	sendfile_listenfd = CreateListenSockfd(PORT_FILE);

	// init epoll
	epollfd = epoll_create(MAX_EVENTS);

    struct epoll_event event_register;
	struct epoll_event event_service;

    event_register.events = EPOLLIN|EPOLLET;
	event_service.events = EPOLLIN|EPOLLET;

    event_register.data.fd = registerfd;
	event_service.data.fd = sevicefd;

	// add event
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, registerfd, &event_register) < 0)
    {
        printf("epoll add fail : fd = %d\n", registerfd);
        return -1;
    }
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sevicefd, &event_service) < 0)
    {
        printf("epoll add fail : fd = %d\n", event_service);
        return -1;
    }

	// epoll
	while (1) {
		// epoll_wait
		epoll_wait_ret = epoll_wait(epollfd, eventlist, MAX_EVENTS, timeout);

		if (epoll_wait_ret < 0){
			perror("epoll epoll_wait_ret error.\n");
			break;
		}else if (epoll_wait_ret == 0){
			printf("no event.\n");
			continue;
		}else{
			for(i = 0; i < epoll_wait_ret; i++){
				if ((eventlist[i].events & EPOLLERR)
				|| (eventlist[i].events & EPOLLHUP)){
				
            	perror("epoll error\n");
            	close(eventlist[i].data.fd);
            	return -1;
            	}
				else if(eventlist[i].data.fd == registerfd){
					pthread_t tid;
					pthread_create(&tid, 0, ServerRegisterService, &registerfd);

				}
				else if(eventlist[i].data.fd == sevicefd){
					Accept(sevicefd);
				}else if (InFilePort(eventlist[i].data.fd)){


				}else{
					user_session us;
					Service(eventlist[i], &us);
				}

			}// end for

		}// end else
	
	}// end while
}

/**
 * @brief user sign out, close all service
 * input : sockfd, 
 * output:none
 * 
 */
void CloseService(int sockfd)
{
	user_session *temppre = &root;
	user_session *temp = (root.next);
	while(temp->next != NULL)
		if (temp->sockfd != sockfd){
			temppre =  temppre->next;
			temp = temp->next;
		}
	temppre->next = temp->next;
	close(sockfd);
	
}

/**
 * @brief create listen sockfd for service
 * input: none
 * output: sockfd
 */
int CreateListenSockfd(int port)
{
	int sockfd;
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) == -1) {
		perror("bind socket failed in CreateListenSockfd.\n");
		return -1;
	}

	if (listen(sockfd, LISTEN_MAX) == -1) {
		perror("listen failed in CreateListenSockfd.\n");
		return -1;
	}

	return sockfd;
}

void Service(struct epoll_event event, user_session *us)
{
	uint8_t* key = NULL;
	
	char buffer[BUFFER_DATASIZE_MAX] = {0};
	char message[BUFFER_DATASIZE_MAX] = {0};
	int sockfd = event.data.fd;

	recvdata(sockfd, buffer, BUFFER_DATASIZE_MAX);

	// check login, set key and save key
	if (strstr(buffer, "\"type\":\"login\"")){

		ServerLoginService(sockfd, buffer, us);

	}else{// other service

		user_session* us = &root;
		while(us){ // get session key
			if(us->sockfd != sockfd)
				us = us->next;
			else{
				key = us->key;
				break;
			}
		} //end while

		if (key == NULL)
			perror("key error, have no session key.\n");

		// decrypt
		RecvWithDec(buffer, key, message);
		printf("message decrypted:\n%s\n", message);

		char type[TYPE_SIZE] = {0};
		char username[USERNAME_MAXSIZE] = {0};
		char subpath[PATH_MAX] = {0};
		int length;
		struct timeb timenow;

		// check
		NormalCheck(message, username, type, "normal_response", sockfd);

		// check username
		if (strcmp(username, us->username) != 0){
			ftime(&timenow);
			memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
			sprintf(buffer, "{\"type\":\"response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
				username, REASON_USERNAME_ERROR, timenow.time * 1000 + timenow.millitm);
		goto send;
		}

		// get subpath
		if (GetWord(message, "path", subpath) == 0){

			if (strcmp(type, "close") == 0){
				CloseService(sockfd);
				printf("link down.\n");
				return;
			}

			ftime(&timenow);
			memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
			sprintf(buffer, "{\"type\":\"response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
				username, REASON_SUBPATH_ERROR, timenow.time * 1000 + timenow.millitm);
		goto send;
		}

		// switch to service
		if (strcmp(type, "upload_file") == 0){
			
			char filename[FILENAME_MAX] = {0};
			if (GetWord(message, "file_dir_name", filename) == 0){
				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"upload_file_response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, REASON_FILENAME_ERROR, timenow.time * 1000 + timenow.millitm);
			goto send;
			}

			if (us->file_upload > FILE_SERVICE_MAX)
				perror("upload file service is full.\n");
			else{
				int sockfd;
				char filesize_str[16] = {0};
				int filefd;
				int filesize;

				struct sockaddr_in fromaddr;
				socklen_t addrlen = sizeof(fromaddr);
				bzero(&fromaddr, addrlen);
	
				if ((sockfd = accept(sendfile_listenfd, (struct sockaddr*)&fromaddr, &addrlen)) == -1) {
					perror("accept socket failed in main.\n");
					return -1;
				}

				GetWord(buffer, "filesize", filesize_str);

				filesize = atoi(filesize_str);

				filefd = CreateFile(username, subpath, filename);

				recv_file file_param;

				file_param.fd = filefd;


				file_param.filesize = filesize;
				file_param.key = key;
				file_param.sockfd =sockfd;
				
				pthread_t tid;
				pthread_create(&tid, 0, RecvFileService, &file_param);

			}

			
			
			


			

		}else if (strcmp(type, "download_file") == 0){
			char filename[FILENAME_MAX] = {0};
			if (GetWord(message, "file_dir_name", filename) == 0){
				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"download_file_response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, REASON_FILENAME_ERROR, timenow.time * 1000 + timenow.millitm);
			goto send;
			}
			if (us->file_download > FILE_SERVICE_MAX)
				perror("download file service is full.\n");
			else{
				

			}






		}else if (strcmp(type, "delete_file") == 0){

			char filename[FILENAME_MAX] = {0};
			if (GetWord(message, "file_dir_name", filename) == 0){
				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"delete_file_response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, REASON_FILENAME_ERROR, timenow.time * 1000 + timenow.millitm);
			goto send;
			}

			DeleteFile(subpath, username, filename);

			ftime(&timenow);
			memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
			sprintf(buffer, "{\"type\":\"delete_file_response\",\"username\":\"%s\",\"state\":\"success\",\"time\":\"%lld\",\"length\":\"00\"}",
				username, timenow.time * 1000 + timenow.millitm);
			goto send;

		}else if (strcmp(type, "create_dir") == 0){

			char dirname[SUBPATH_MAX] = {0};
			if (GetWord(message, "file_dir_name", dirname) == 0){

				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"create_dir_response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, REASON_DIRNAME_ERROR, timenow.time * 1000 + timenow.millitm);
			goto send;
			}

			CreateDir(subpath, username, dirname);

			ftime(&timenow);
			memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
			sprintf(buffer, "{\"type\":\"create_dir_response\",\"username\":\"%s\",\"state\":\"success\",\"time\":\"%lld\",\"length\":\"00\"}",
				username, timenow.time * 1000 + timenow.millitm);
			goto send;

		}else if (strcmp(type, "delete_dir") == 0){

			char dirname[SUBPATH_MAX] = {0};
			if (GetWord(message, "file_dir_name", dirname) == 0){
				ftime(&timenow);
				memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
				sprintf(buffer, "{\"type\":\"delete_dir_response\",\"username\":\"%s\",\"state\":\"fail\",\"reason\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, REASON_DIRNAME_ERROR, timenow.time * 1000 + timenow.millitm);
			goto send;
			}
			
			DeleteDir(subpath, username, dirname);

			ftime(&timenow);
			memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
			sprintf(buffer, "{\"type\":\"delete_dir_response\",\"username\":\"%s\",\"state\":\"success\",\"time\":\"%lld\",\"length\":\"00\"}",
				username, timenow.time * 1000 + timenow.millitm);
			goto send;
		}

		return;

		send:
    	{
    	length = strlen(buffer);
		InsertLength(buffer, length);
		SendWithEnc(buffer, key, sockfd);
		printf("send data in Service:\n%s\nlength:%d\n", buffer, length);
    	}

	}

	// pthread_exit(0);
	return;
}

int main()
{
	root.sockfd = 0;
	memset(root.key, 0x00, BIG8W_BYTESIZE);
	root.next = NULL;

	rear = &root;

	fd_root.fd = 0;
	fd_root.sockfd = 0;
	fd_root.next = NULL;
	fd_rear = &fd_root;

    ServerInit_ECC();

	if (ServerService() == -1){
		printf(" ServerService end with error.\n");
	}

	return 0;

}