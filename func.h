#include <stdint.h>
#include <string.h>

#include "eccipccom.h"

uint8_t GetWord(char* buffer, char* key, char* value);
void Base64Encode(uint8_t* msg, uint32_t length, char* res);
void Base64Decode(char* string, uint32_t length, uint8_t* res);
int LenStrToInt(char* lenstr);
void InsertLength(char* buffer, int32_t length);

void SM4EncryptWithEcbMode(uint8_t* message, uint32_t msglen, uint8_t* key, uint8_t* ciphertext);
void SM4DecryptWithEcbMode(uint8_t* ciphertext, uint32_t ciphertextlen, uint8_t* message, int msglen, uint8_t* key);

void SendEncryptedBuffer(char* buffer, uint8_t* key, int sockfd);

int recvdata(int sockfd, char* buffer, int buffersize);
void senddata(int sockfd, char* data, int datalen);
int PasswdIsWeak(char* passwd);

void SendWithEnc(uint8_t *message, uint8_t *key, int sockfd);
void RecvWithDec(char* buffer, uint8_t *key, uint8_t *msg);
