#include "file.h"

#define USER_TOP_DIR "/home/lwy/sendfile/"
#define BLOCK_SIZE 1024
#define BLOCK_LEFT_SHIFT 10

#define PORT_FILE 8082

// void MessagePretreatment(char* buffer, char* type)
// {
//     struct timeb timenow;
    
//     if (((GetWord(buffer, (char*)"length", type) == 0)) && (strlen(buffer) != LenStrToInt(type)))
//         perror("type error")
    
// }

void Chdir(char* username, char* subpath)
{
    chdir(USER_TOP_DIR);
    chdir(username);
    chdir(subpath);
}

void CreateDir(char* subpath, char* username, char* dirname)
{
    Chdir(username, subpath);

    if (mkdir(dirname, 0774) == -1)
        perror("create directory error.\n");
    else
        printf("directory %s is created successfully.\n", dirname);

}

void DeleteDirCascade(char* dirname)
{
    DIR *subdir;
    struct dirent *entry;
    struct stat statbuf;

    if ((subdir = opendir(dirname)) == NULL){
        perror("open directory failed.\n");
    }
    chdir(dirname);
    while(entry = readdir(subdir)){
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode)){
            if (strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0)
                continue;
            else{
                DeleteDirCascade(entry->d_name);
            }
        }
        else{
            if(unlink(entry->d_name) == -1){
                perror("delete file failed.\n");
            }else{
                printf("file %s is deleted.\n", entry->d_name);
            }
        }
    }

    chdir("..");
    printf("delete dir:%s\n", dirname);
    if(rmdir(dirname) == -1){
        perror("delete file failed.\n");
    }else{
        printf("file %s is deleted.\n", dirname);
    }
    

}

void DeleteDir(char* subpath, char* username, char* dirname)
{
    Chdir(username, subpath);

    DeleteDirCascade(dirname);
}

int CreateFile(char* username, char* path, char* filename)
{
    int fd;

    char cpath[128] = {0};

    chdir(USER_TOP_DIR);
    chdir(username);
    chdir(path);

    if((fd = open(filename, (O_CREAT|O_RDWR), (S_IRUSR|S_IWUSR))) == -1){
        perror("file create failed.\n");
        return -1;
    }else
        printf("file %s is created successfully.\n", filename);
    close(fd);
    if((fd = open(filename, (O_RDWR), (S_IRUSR|S_IWUSR))) == -1){
        perror("file create failed.\n");
        return -1;
    }
    return fd;
}

void ClientCreateInfo(char* buffer)
{
    int fd;
    char filename[] = "info.txt";

    if((fd = (open(filename, (O_CREAT|O_RDWR), (S_IRUSR|S_IWUSR)))) == -1)
        perror("info.txt file create failed.\n");
    else
        printf("file %s is created successfully.\n", filename);
    
    if (write(fd, buffer, 128) < 0){
        perror("file info.txt write failed.\n");
    }
    close(fd);
}

void ClientGetChallenge(uint8_t* challenge)
{
    int fd;
    char filename[] = "info.txt";
    char buffer[128] = {0};
    char encoded_challenge[64] = {0};
    if ((fd = (open(filename, (O_RDONLY)))) == -1)
        perror("info.txt file open failed.\n");
    
    if (read(fd, buffer, 128) < 0){
        perror("file info.txt read failed.\n");
    }
    close(fd);

    // printf("buffer in ClientGetChallenge:\n%s\n", buffer);
    
    GetWord(buffer, "challenge", encoded_challenge);
    Base64Decode(encoded_challenge, strlen(encoded_challenge), challenge);
}

void ClientRefreshChallenge(char* new_challenge)
{
    int fd;

    char filename[] = "info.txt";
    char buffer[128] = {0};
    char encoded_challenge[64] = {0};

    char* start;

    char challenge[] = "{\"challenge\":\"";

    if ((fd = (open(filename, (O_RDWR)))) == -1)
        perror("info.txt file open failed.\n");
    
    if (read(fd, buffer, 128) < 0){
        perror("file info.txt read failed.\n");
    }

    close(fd);

    if ((fd = (open(filename, (O_RDWR|O_TRUNC)))) == -1)
        perror("info.txt file open failed.\n");
    
    start =strstr(buffer, challenge);
    start += strlen(challenge);

    for (int i = 0; i < 44; i++)
        start[i] = new_challenge[i];
    
    // printf("challenge in info.txt, after change:\n%s\n", buffer);

    if(write(fd, buffer, strlen(buffer)) < 0)
        perror("write new challenge error.\n");

    close(fd);
}

void DeleteFile(char* subpath, char* username, char* filename)
{
    Chdir(username, subpath);

    if(unlink(filename) == -1)
        perror("file create failed.\n");
    else
        printf("file %s is created successfully.\n", filename);
}

int GetFilesize(char* path, char* filename)
{
    chdir(path);
    struct stat statbuf;

    chdir(path);

    lstat(filename, &statbuf);
    if (S_ISDIR(statbuf.st_mode))
        perror("Is a directory.\n");
    
    return statbuf.st_size;
}


void SendFileService(void *sendfile)
{
    send_file param = *(send_file*)sendfile;

    char *path = param.path;
    char* filename = param.filename;
    int sockfd = param.sockfd;
    uint8_t* key = param.key;

    uint8_t buffer[BLOCK_SIZE] = {0};
    uint8_t ciphertext[BLOCK_SIZE] = {0};
    char ciphertext_encoded[BLOCK_SIZE + (BLOCK_SIZE > 1)] = {0};
    int fd;
    uint32_t index = 0;

    uint32_t breakpoint = 0;

    struct stat statbuf;

    chdir(path);

    lstat(filename, &statbuf);
    if (S_ISDIR(statbuf.st_mode))
        perror("Is a directory.\n");
    
    fd = open(filename, O_RDONLY);

    while(1){
        memset(buffer, 0x00, BLOCK_SIZE);
        breakpoint += read(fd, buffer, BLOCK_SIZE - 1);
        // printf("buffer data of file:%s\n", buffer);
        // SM4EncryptWithEcbMode(buffer, BLOCK_SIZE, key, ciphertext);
        // Base64Encode(ciphertext, BLOCK_SIZE, ciphertext_encoded);
        // senddata(sockfd, ciphertext_encoded, strlen(ciphertext_encoded));
        senddata(sockfd, buffer, strlen(buffer));
        // printf("breakpoint:%d\n", breakpoint);
        if (breakpoint == statbuf.st_size)
            break;    
    }
}

void RecvFileService(void* fileparam)
{
    recv_file file_param = *(recv_file*)fileparam;
    int filesize = file_param.filesize;
    int fd = file_param.fd;
    int sockfd = file_param.sockfd;
    uint8_t* key = file_param.key;

    uint8_t buffer[BLOCK_SIZE] = {0};
    uint8_t ciphertext[BLOCK_SIZE] = {0};
    char ciphertext_encoded[BLOCK_SIZE + (BLOCK_SIZE > 1)] = {0};
    int write_return;
    int length;
    uint32_t breakpoint = 0;

    while(1){
        memset(buffer, 0x00, BLOCK_SIZE);
        recvdata(sockfd, buffer, BLOCK_SIZE - 1);
        // memset(ciphertext_encoded, 0x00, BLOCK_SIZE + (BLOCK_SIZE > 1));
        // recvdata(sockfd, ciphertext_encoded, BLOCK_SIZE + (BLOCK_SIZE > 1));
        // Base64Decode(ciphertext_encoded, strlen(ciphertext_encoded), ciphertext);
        // length = (strlen(ciphertext_encoded) >> 2) * 3;
        // SM4DecryptWithEcbMode(ciphertext, length, buffer, length, key);
        // printf("recvdata:\n%s\n", buffer);
        write_return = write(fd, buffer, strlen(buffer));
        if (write_return < 0)
            perror("write error when receive data.\n");
        breakpoint += write_return;
        // printf("breakpoint:%d\n", breakpoint);
        if (breakpoint == filesize)
            break;    
    }

    printf("RecvFileService before close.\n");
    close(fd);
    close(sockfd);

}

void CreateUserFile(char* username, uint8_t* hashvalue, char* encoded_challenge)
{
    char filename[32] = {0};
    uint8_t key[BIG8W_BYTESIZE] = {0};
    uint8_t ciphertext[BIG8W_BYTESIZE] = {0};
    char wr[BIG8W_BYTESIZE * 2] = {0};
    int wr_len = 44;  // (32 encoded to 44)
    int fd;
    char buffer[128] = {0};

    chdir(USER_TOP_DIR);
    chdir(username);

    sprintf(filename, ".info_%s", username);
    
    if((fd = open(filename, (O_CREAT|O_RDWR), (S_IRUSR|S_IWUSR))) == -1)
        perror("file .info_username create failed.\n");

    Big8wIntou8string(&k1, key, 0);

    SM4EncryptWithEcbMode(hashvalue, SM3OUT_32BYTES, key, ciphertext);
    Base64Encode(ciphertext, BIG8W_BYTESIZE, wr);

    sprintf(buffer, "{\"challenge\":\"%s\",\"hashpasswd\":\"%s\"}", encoded_challenge, wr);

    if (write(fd, buffer, strlen(buffer)) < 0)
        perror("write error when create file for user.\n");
}

void GetHashvalue(char* username, uint8_t* hashvalue, uint8_t* challenge)
{
    int fd;
    int length;

    char filename[32] = {0};
    char wr[BIG8W_BYTESIZE * 2] = {0};
    char buffer[128] = {0};
    uint8_t key[BIG8W_BYTESIZE] = {0};
    uint8_t ciphertext[BIG8W_BYTESIZE] = {0};
    sprintf(filename, ".info_%s", username);

    chdir(USER_TOP_DIR);
    chdir(username);

    if( (fd = open(filename, (O_RDWR))) == -1)
        perror("open file error when read user info file.\n");
    else
        length = read(fd, buffer, 128);

    Big8wIntou8string(&k1, key, 0);

    if (length == -1)
        perror("read user info file failed.\n");

    if (GetWord(buffer, "hashpasswd", wr) == 0){
        perror(".info_username have no hashpasswd.\n");
    }

    Base64Decode(wr, strlen(wr), ciphertext);
    SM4DecryptWithEcbMode(ciphertext, BIG8W_BYTESIZE, hashvalue, BIG8W_BYTESIZE, key);

    memset(wr, 0x00, BIG8W_BYTESIZE * 2);
    memset(ciphertext, 0x00, BIG8W_BYTESIZE);

    if (GetWord(buffer, "challenge", wr) == 0){
        perror(".info_username have no hashpasswd.\n");
    }

    Base64Decode(wr, strlen(wr), challenge);
}

uint8_t AddUser(char* username, char* hashvalue, char* encoded_challenge)
{
    DIR *subdir;
    struct dirent *entry;
    struct stat statbuf;

    if ((subdir = opendir(USER_TOP_DIR)) == NULL){
        perror("open directory failed.\n");
    }

    while(entry = readdir(subdir)){
        lstat(entry->d_name, &statbuf);
        if (strcmp(username, entry->d_name) == 0 ){
            perror("username is occupied.\n");
            return 0;
        }
    }

    if (mkdir(username, 0744) == -1)
        perror("mkdir faild, user added failed.\n");
    else
        printf("user %s is added.\n", username);
    
    CreateUserFile(username, hashvalue, encoded_challenge);
    
    return 1;
}

void DeleteUser(char* username)
{
    chdir(USER_TOP_DIR);

    DeleteDirCascade(username);
}