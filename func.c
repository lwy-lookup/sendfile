#include "func.h"

#define BUFFER_DATASIZE_MAX 1024

uint8_t GetWord(char* buffer, char* key, char* value)
{
	char* temp;
    int32_t i = 0;

    temp = strstr(buffer, key);
    if (temp == NULL) {
        printf("The segment %s is not in the buffer string\n", key);
        return 0;
    }

    temp += strlen(key) + strlen("\":\"");
    while (temp[i] != '\"') {
        value[i] = temp[i];
        i++;
    }

    return 1;
}

char Base64EncodeAffine(char word)
{
	if (word < 0)
		return -1;
	else if (word < 26)
		return 'A' + word;
	else if (word < 52)
		return 'a' + (word - 26);
	else if (word < 62)
		return '0' + (word - 52);
	else if (word == 62)
		return '-';
	else if (word == 63)
		return '_';
	else return -1;
}

char Base64DecodeAffine(char word)
{
	if (word >= 'A' && word <= 'Z')
		return word - 'A';
	else if (word >= 'a' && word <= 'z')
		return word - 'a' + 26;
	else if (word >= '0' && word <= '9')
		return word - '0' + 52;
	else if (word == '-')
		return 62;
	else if (word == '_')
		return 63;
	else if (word == '=')
		return 0;

}

void Base64Encode(uint8_t* msg, uint32_t length, char* res)
{
	uint32_t i, index = 0, elem;
	char rest = length % 3;

	if (length == 0)
		return;

	for (i = 0; i + 2 < length; i += 3) {
		elem = 0;
		elem += ((uint32_t)msg[i]) << 16;
		elem += ((uint32_t)msg[i + 1]) << 8;
		elem += ((uint32_t)msg[i + 2]);

		res[index++] = Base64EncodeAffine((elem >> 18) & 0x3f);
		res[index++] = Base64EncodeAffine((elem >> 12) & 0x3f);
		res[index++] = Base64EncodeAffine((elem >> 6) & 0x3f);
		res[index++] = Base64EncodeAffine(elem & 0x3f);
	}

	if (rest) {
		if (rest == 1) {
			elem = 0;
			elem += ((uint32_t)msg[i]) << 16;
			res[index++] = Base64EncodeAffine((elem >> 18) & 0x3f);
			res[index++] = Base64EncodeAffine((elem >> 12) & 0x3f);
			res[index++] = '=';
			res[index++] = '=';
		}

		else if (rest == 2) {
			elem = 0;
			elem += ((uint32_t)msg[i++]) << 16;
			elem += ((uint32_t)msg[i++]) << 8;

			res[index++] = Base64EncodeAffine((elem >> 18) & 0x3f);
			res[index++] = Base64EncodeAffine((elem >> 12) & 0x3f);
			res[index++] = Base64EncodeAffine((elem >> 6) & 0x3f);
			res[index++] = '=';
		}

	}

}

void Base64Decode(char* string, uint32_t length, uint8_t* res)
{
	uint32_t i, index = 0, elem;
	if (length == 0 || (length & 0x3))
		return;

	for (i = 0; i < length - 4; i += 4) {
		elem = 0;
		elem += ((uint32_t)(Base64DecodeAffine(string[i]))) << 18;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 1]))) << 12;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 2]))) << 6;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 3])));

		res[index++] = (elem >> 16);
		res[index++] = (elem >> 8);
		res[index++] = elem;

	}

	if (string[i + 2] == '=') {
		elem = 0;
		elem += ((uint32_t)(Base64DecodeAffine(string[i]))) << 18;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 1]))) << 12;

		res[index++] = (elem >> 16);
	}

	else if (string[i + 3] == '=') {
		elem = 0;
		elem += ((uint32_t)(Base64DecodeAffine(string[i]))) << 18;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 1]))) << 12;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 2]))) << 6;

		res[index++] = (elem >> 16);
		res[index++] = (elem >> 8);
	}

	else {
		elem = 0;
		elem += ((uint32_t)(Base64DecodeAffine(string[i]))) << 18;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 1]))) << 12;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 2]))) << 6;
		elem += ((uint32_t)(Base64DecodeAffine(string[i + 3])));

		res[index++] = (elem >> 16);
		res[index++] = (elem >> 8);
		res[index++] = elem;
	}
}

char numtochar(uint8_t num)
{
	if (num < 10)
		return '0' + num;
	return 'a' + (num - 10);
}

uint8_t CharToNum(char ch)
{
	if ('0' <= ch && '9' >= ch)
		return ch - '0';
	else if ('a' <= ch && 'f' >= ch)
		return ch - 'a' + 10;
	else
		return -1;
}

int LenStrToInt(char* lenstr)
{
	int length = 0;
	for (int i = 0; i < strlen(lenstr); i++)
		if (CharToNum(lenstr[i]) != -1)
			length = (length << 4) + CharToNum(lenstr[i]);
		else
			return -1;
	// printf("length in LenStrToInt:%d\n", length);
	return length;
}

void InsertLength(char* buffer, int32_t length)
{
	int32_t bufferlen = strlen(buffer);

	uint8_t low = length & 0xf;
	uint8_t high = length >> 4;

	buffer[bufferlen - 3] = numtochar(low);
	buffer[bufferlen - 4] = numtochar(high);

	// printf("buffer in InsertLength:\n%s\nlength:%d\n", buffer, length);

}


/**
 * @brief SM4 Encrypt Function With ecb mode
 * 
 * @param message data to be encrypted
 * @param msglen length of message, byte size
 * @param key key of SM4 algorithm
 * @param ciphertext unsigned char string to store the encrypted message
 * 
 * @result ciphertext
 * 
 */
void SM4EncryptWithEcbMode(uint8_t* message, uint32_t msglen, uint8_t* key, uint8_t* ciphertext)
{
	sms4_key_t renckey;
	uint32_t ciphertextlen = 0;
	sms4_set_encrypt_key(&renckey, key);
	sms4_ecb_encrypt_pkcs7padding(message, msglen, ciphertext, &ciphertextlen, &renckey);
}
/**
 * @brief SM4 Decrypt Function 
 * 
 * @param ciphertext encrypted message to be decrypted
 * @param ciphertextlen length of ciphertext,  % 128 == 0
 * @param message unsigned char string to store decrypted data
 * @param msglen length of message
 * @param key key of SM4 algorithm
 * 
 * @result message
 * 
 */
void SM4DecryptWithEcbMode(uint8_t* ciphertext, uint32_t ciphertextlen, uint8_t* message, int msglen, uint8_t* key)
{
	sms4_key_t rdeckey;
	sms4_set_decrypt_key(&rdeckey, key);
	sms4_ecb_decrypt_pkcs7padding(ciphertext, ciphertextlen, message, &msglen, &rdeckey);
}

void SendEncryptedBuffer(char* buffer, uint8_t* key, int sockfd)
{
    uint8_t encrypted_buffer[BUFFER_DATASIZE_MAX] = {0};
    char sendbuffer[BUFFER_DATASIZE_MAX] = {0};
    uint8_t encrypted_buffer_length;

    SM4EncryptWithEcbMode((uint8_t*)buffer, strlen(buffer), key, encrypted_buffer);

    encrypted_buffer_length = strlen(buffer);
    encrypted_buffer_length = ((encrypted_buffer_length >> 4) << 4) + SMS4_BLOCK_SIZE;

    Base64Encode(encrypted_buffer, encrypted_buffer_length, sendbuffer);
	printf("sendbuffr in SendEncryptedBuffer:\n%s\n", sendbuffer);
    senddata(sockfd, sendbuffer, strlen(sendbuffer));
}


int recvdata(int sockfd, char* buffer, int buffersize)
{
	int recvsize = 0;
    while(recvsize <= 0)
        recvsize = recv(sockfd, buffer, buffersize, 0);
        
    return recvsize;
}

void senddata(int sockfd, char* data, int datalen)
{
	send(sockfd, data, datalen, 0);
}

int PasswdIsWeak(char* passwd)
{
	return 0;
}

void SendWithEnc(uint8_t *message, uint8_t *key, int sockfd)
{
  uint8_t *ciphertext, *msgsend;
  uint32_t length = strlen((char*)message);

  int ciphertext_len = ((length >> 4) << 4) + 16;
  
  ciphertext = (uint8_t*)(malloc(length + 32));
  msgsend = (char*)(malloc(length * 2 + 128));
  memset(ciphertext, 0x00, length + 32);
  memset(msgsend, 0x00, length * 2 + 128);

  SM4EncryptWithEcbMode(message, length, key, ciphertext);

  Base64Encode(ciphertext, ciphertext_len, msgsend);

  senddata(sockfd, msgsend, strlen(msgsend));
  free(ciphertext);
  free(msgsend);
}

void RecvWithDec(char* buffer, uint8_t *key, uint8_t *msg)
{
  char *msglen_index;
  uint8_t *msgdecode;
  uint8_t msglen_uint8str[4] = {0};
  int bufferlen = strlen(buffer);
  int msglen = 0;

  msgdecode = (uint8_t*)(malloc(bufferlen));
  memset(msgdecode, 0x00, bufferlen);

  msglen = ((bufferlen >> 2) * 3 );
  msglen = (msglen >> 4) << 4;

  printf("buffer of EccRecvWithDec:\n%s\n", buffer);

  Base64Decode(buffer, bufferlen, msgdecode);

  printf("msglen:%d\n", msglen);

  SM4DecryptWithEcbMode(msgdecode, msglen, msg, msglen, key);
  free(msgdecode);
}