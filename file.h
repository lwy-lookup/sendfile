#include "func.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct recv_file_pthread_struct{
    int filesize;
    uint8_t* key;
    int fd;
    int sockfd;
} recv_file;

typedef struct senfile_pthread_struct{
    char path[PATH_MAX];
    char filename[FILENAME_MAX];
    uint8_t *key;
    int sockfd;
} send_file;


void Chdir(char* username, char* subpath);
void CreateDir(char* subpath, char* username, char* dirname);
void DeleteDir(char* subpath, char* username, char* dirname);
int CreateFile(char* username, char* path, char* filename);
void DeleteFile(char* subpath, char* username, char* filename);

void ClientCreateInfo(char* buffer);
void ClientGetChallenge(uint8_t* challenge);
void ClientRefreshChallenge(char* new_challenge);

int GetFilesize(char* path, char* filename);

void SendFileService(void *sendfile);
void RecvFileService(void* fileparam);

void GetHashvalue(char* username, uint8_t* hashvalue, uint8_t* challenge);
uint8_t AddUser(char* username, char* hashvalue, char* encoded_challenge);
void DeleteUser(char* username);