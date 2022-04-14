#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <sys/socket.h>

#include "file.h"

#define CONNECT_REGISTER 1
#define CONNECT_SERVICE 2
#define CONNECT_FILE 3

#define USERNAME_MAXSIZE 16
#define PASSWD_MAXSIZE 16
#define BUFFER_DATASIZE_MAX 1024

#define SERVER_IPV4ADDR_STRING "127.0.0.1"
#define SERVERPORT_REGISTER 8080
#define SERVERPORT_SERVICE 8081
#define PORT_FILE 8082

char encoded_pubkey_string[] = "xmfXt48TER40UhVdhq1sWe0zRiE0C-a0oZzVN1wpVR6foFAs9NTurats-tM5oVlgwiRwf6Bv8NL043wJWv95Y1ujsVNUSYPi57-vZ_IZayTRhVBOztQxu2JLBzSRJJ5ipW5uRIbIlogl42z5jXydRESLv6VGjsjnPfvucl3E1Ws=";
uint8_t challenge[BIG8W_BYTESIZE] = {0};
char username[USERNAME_MAXSIZE] = {0};
uint8_t key[BIG8W_BYTESIZE] = {0};

void ClientInit()
{
    int i = 0;
    unsigned char pubkey_string[BIG8W_BYTESIZE * 4 + 4] = {0};
    Base64Decode(encoded_pubkey_string, strlen(encoded_pubkey_string), pubkey_string);

    EccIBEInit();

    for(i = 0; i < BIGNUMBER_SIZE_8WORD; i++)
        PubKey1.x.word[i] = GETU32(pubkey_string + i * 4);
    for(; i < BIGNUMBER_SIZE_8WORD * 2; i++)
        PubKey1.y.word[i - BIGNUMBER_SIZE_8WORD] = GETU32(pubkey_string + i * 4);
    for(i; i < BIGNUMBER_SIZE_8WORD * 3; i++)
        PubKey2.x.word[i - BIGNUMBER_SIZE_8WORD * 2] = GETU32(pubkey_string + i * 4);
    for(; i < BIGNUMBER_SIZE_8WORD * 4; i++)
        PubKey2.y.word[i - BIGNUMBER_SIZE_8WORD* 3] = GETU32(pubkey_string + i * 4);
}

int ClientConnectServer(int port)
{
    int sockfd;

    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("error when create socket in client\n");

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    if (inet_pton(AF_INET, SERVER_IPV4ADDR_STRING, &servaddr.sin_addr) < 0){
        perror("error in inet_pton, in client\n");
    }

    if (connect(sockfd, (struct sockaddr*)(&servaddr), sizeof(servaddr)) < 0){
        perror("error in connect, in client\n");
    }

    return sockfd;
}

int RegisterResponseCheck(uint8_t* hashvalue, int sockfd)
{
    char buffer[BUFFER_DATASIZE_MAX] = {0};

    char state[8] = {0};
    char encoded_ciphertext[64] = {0};
    char encoded_challenge[64] = {0};
    uint8_t ciphertext[BIG8W_BYTESIZE] = {0};
    char reason[32] = {0};
    
    recvdata(sockfd, buffer, BUFFER_DATASIZE_MAX - 1);

    if ((GetWord(buffer, "state", state)) && (strcmp(state, "success") == 0)){

        GetWord(buffer, "ciphertext", encoded_ciphertext);
        GetWord(buffer, "challenge", encoded_challenge);
        Base64Decode(encoded_ciphertext, strlen(encoded_ciphertext), ciphertext);
        // Base64Decode(encoded_challenge, strlen(encoded_challenge), challenge);

        for(int i = 0; i < BIG8W_BYTESIZE; i++)
            ciphertext[i] ^= hashvalue[i];
        U8StringToBig8w(ciphertext, &client_secretkey);

        memset(buffer, 0x00, BUFFER_DATASIZE_MAX);
        sprintf(buffer, "{\"challenge\":\"%s\",\"encrypted_sk\",\"%s\"}", encoded_challenge, encoded_ciphertext);
        printf("buffer to info:\n%s\n", buffer);
        ClientCreateInfo(buffer);
        printf("register success.\n");
        
    }
    else{
        perror("register failed.\n");
        return 0;
    }

    return 1;
}

void Register(char* username, char* passwd, char* passwd_cmp, int sockfd) {
	char* buffer;
    char* passwd_cipher;

	if (strcmp(passwd, passwd_cmp) != 0) {
		perror("The tow passwords is not the same.\n");
	}
	else if (sizeof(passwd) <= 6) {
		perror("The passwd is too short.\n");
	}
	else if (sizeof(passwd) >= PASSWD_MAXSIZE) {
		perror("The passwd is too long.\n");
	}
	else if (PasswdIsWeak(passwd)) {
		perror("The passwd is too weak.\n");
	}
	else {
		buffer = (char*)(malloc(BUFFER_DATASIZE_MAX));
		memset(buffer, 0x00, BUFFER_DATASIZE_MAX);

        passwd_cipher = (char*)(malloc(160));

		struct timeb timenow;
		ftime(&timenow);

        uint8_t hashvalue[SM3OUT_32BYTES] = {0};
        sm3((uint8_t*)passwd, strlen(passwd), hashvalue);

        EccEnc_SM2EncMode(hashvalue, SM3OUT_32BYTES, PubKey1, passwd_cipher, passwd_cipher + 88);

		sprintf(buffer, "{\"type\":\"register\",\"username\":\"%s\",\"passwd_cipher\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, passwd_cipher, timenow.time * 1000 + timenow.millitm);

		InsertLength(buffer, strlen(buffer));

        printf("register data:\n%s\n", buffer);

		senddata(sockfd, buffer, strlen(buffer));

        if(RegisterResponseCheck(hashvalue, sockfd) == 0){
            perror(" register failed.\n");
        }

        close(sockfd);

        free(buffer);
        free(passwd_cipher);
	}
}

void Login(char* username, char* passwd, int sockfd)
{
    char* buffer;
    uint8_t hashvalue[SM3OUT_32BYTES] = {0};

    char passwd_cipher[160] = {0};

    buffer = (char*)(malloc(BUFFER_DATASIZE_MAX));
	memset(buffer, 0x00, BUFFER_DATASIZE_MAX);

    sm3((uint8_t*)passwd, strlen(passwd), hashvalue);
    ClientGetChallenge(challenge);

    for(int i = 0; i < SM3OUT_32BYTES; i++)
        hashvalue[i] ^= challenge[i];
    
    EccEnc_SM2EncMode((char*)hashvalue, SM3OUT_32BYTES, PubKey1, passwd_cipher, passwd_cipher + 88);
    
    struct timeb timenow;
	ftime(&timenow);

    sprintf(buffer, "{\"type\":\"login\",\"username\":\"%s\",\"passwd_cipher\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
			username, passwd_cipher, timenow.time * 1000 + timenow.millitm);

    InsertLength(buffer, strlen(buffer));

    printf("login data:\n%s\n", buffer);

	senddata(sockfd, buffer, strlen(buffer));
}

void LoginResponseCheck(char* passwd, int sockfd)
{
    char buffer[BUFFER_DATASIZE_MAX] = {0};
    char setkey[BIG8W_BYTESIZE * 2] ={0};
    char new_challenge[BIG8W_BYTESIZE * 2] = {0};
    char state[16] = {0};
    uint8_t key_decoded[BIG8W_BYTESIZE] = {0};

    uint8_t hashvalue[SM3OUT_32BYTES] = {0};

    sm3((uint8_t*)passwd, strlen(passwd), hashvalue);

    recvdata(sockfd, buffer, BUFFER_DATASIZE_MAX);

    printf("login response data received from server:\n%s\n", buffer);

    if (strstr(buffer, "success") != NULL)
        printf("client login success.\n");
    
    if (GetWord(buffer, "setkey", setkey) == 0){
        perror("server data error, no setkey.\n");
    }
    if (GetWord(buffer, "challenge", new_challenge) == 0){
        perror("server data error, no challenge.\n");
    }

    Base64Decode(setkey, strlen(setkey), key_decoded);

    for (int i = 0; i < BIG8W_BYTESIZE; i++){
        key[i] = key_decoded[i] ^ hashvalue[i];
    }

    ClientRefreshChallenge(new_challenge);
}

void ClientFileOp(char* subpath, char* dirname, char* op, int sockfd)
{
    char buffer[BUFFER_DATASIZE_MAX] = {0};
    
    struct timeb timenow;

	ftime(&timenow);
    sprintf(buffer, "{\"type\":\"%s\",\"username\":\"%s\",\"path\":\"%s\",\"file_dir_name\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
                op, username, subpath, dirname, timenow.time * 1000 + timenow.millitm);
    InsertLength(buffer, strlen(buffer));

    SendEncryptedBuffer(buffer, key, sockfd);    
}

void ClientCreateDir(char* subpath, char* dirname, int sockfd)
{
    ClientFileOp(subpath, dirname, "create_dir", sockfd);
}

void ClientDeleteDir(char* subpath, char* dirname, int sockfd)
{
    ClientFileOp(subpath, dirname, "delete_dir", sockfd);
}

void SendFile(char* path, char* filename, int sockfd)
{
    int filesize = GetFilesize(path, filename);
    char buffer[BUFFER_DATASIZE_MAX] = {0};
    
    struct timeb timenow;

	ftime(&timenow);
    sprintf(buffer, "{\"type\":\"upload_file\",\"username\":\"%s\",\"path\":\"%s\",\"file_dir_name\":\"%s\",\"filesize\":\"%ld\",\"time\":\"%lld\",\"length\":\"00\"}",
                username, path, filename, filesize, timenow.time * 1000 + timenow.millitm);
    InsertLength(buffer, strlen(buffer));

    SendEncryptedBuffer(buffer, key, sockfd); 
}

void RecvFile(char* subpath, char* filename, int sockfd)
{
    ClientFileOp(subpath, filename, "download_file", sockfd);
}

void ClientDeleteFile(char* subpath, char* filename, int sockfd)
{
    ClientFileOp(subpath, filename, "delete_file", sockfd);
}

void ClientClose(int sockfd)
{
    char buffer[BUFFER_DATASIZE_MAX] = {0};
    
    struct timeb timenow;

	ftime(&timenow);
    sprintf(buffer, "{\"type\":\"close\",\"username\":\"%s\",\"time\":\"%lld\",\"length\":\"00\"}",
                username, timenow.time * 1000 + timenow.millitm);
    InsertLength(buffer, strlen(buffer));

    SendEncryptedBuffer(buffer, key, sockfd); 
}


void main()
{
    int registerfd, servicefd;

    strcpy(username, "lwy");

    ClientInit();
    registerfd = ClientConnectServer(SERVERPORT_REGISTER);

    Register(username, "123456", "123456", registerfd);

    servicefd = ClientConnectServer(SERVERPORT_SERVICE);

    Login(username, "123456", servicefd);

    LoginResponseCheck("123456", servicefd);

    ClientCreateDir(".", "createdir", servicefd);

    sleep(3);

    // ClientDeleteDir(".", "createdir", servicefd);

    // sleep(3);


    int filefd;
    filefd = ClientConnectServer(PORT_FILE);
    SendFile("createdir", "bignum.c", servicefd);

    pthread_t tid;
    send_file param;
    
    strcpy(param.filename, "bignum.c");
    strcpy(param.path, ".");

    param.sockfd = filefd;
    param.key = key;
    pthread_create(&tid, 0, SendFileService, &param);

    // char instruct;
    // while(1){

    //     int filefd;
    //     filefd = ClientConnectServer(PORT_FILE);

    //     send_file param;

    //     scanf("%c", &instruct);

    //     if (instruct == '0')
    //         break;
    //     else if (instruct == '1'){

    //         SendFile("createdir", "bignum.c", servicefd);

    //         strcpy(param.filename, "bignum.c");

    //         strcpy(param.path, ".");

    //         param.sockfd = filefd;

    //         param.key = key;

    //         pthread_t tid;
    //         pthread_create(&tid, 0, SendFileService, &param);
            
    //     }else if (instruct == '2'){
            
    //         SendFile("createdir", "sm3.c", servicefd);

    //         strcpy(param.filename, "sm.c");

    //         strcpy(param.path, ".");

    //         param.sockfd = filefd;

    //         param.key = key;

    //         pthread_t tid;
    //         pthread_create(&tid, 0, SendFileService, &param);

    //     }else if (instruct == '3'){
            
    //         SendFile("createdir", "ecc.c", servicefd);

    //         strcpy(param.filename, "ecc.c");

    //         strcpy(param.path, ".");

    //         param.sockfd = filefd;

    //         param.key = key;

    //         pthread_t tid;
    //         pthread_create(&tid, 0, SendFileService, &param);
    //     }else if (instruct == '4'){
            
    //         SendFile("createdir", "sm2.c", servicefd);

    //         strcpy(param.filename, "sm2.c");

    //         strcpy(param.path, ".");

    //         param.sockfd = filefd;

    //         param.key = key;

    //         pthread_t tid;
    //         pthread_create(&tid, 0, SendFileService, &param);
    //     }
        
    // }

    sleep(3);

    ClientClose(servicefd);
    
}