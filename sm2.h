#ifndef SM2_H
#define SM2_H

#include "ecc.h"

extern G1point P, PubKey1, PubKey2;
extern big8w k1, k2;;

void SM2GetZ(char* ID, int IDlen, big8w a, big8w b, G1point* P, G1point* pubkey, unsigned char* Z);

void SM2Sign(char* message, int msglen, char* ID_self, int IDlen, big8w a, big8w b, 
                G1point* P, G1point* pubkey, big8w secretkey, unsigned char* signature);
bool SM2VerifySign(char* message, int msglen, char* ID_self, int IDlen, big8w a, big8w b, 
                G1point* P, G1point* pubkey, unsigned char* signature);

bool EccEnc_SM2EncMode(char* message, int msglen, G1point pubkey_counterpart, char* encoded_C1string, char* encoded_C2string);
bool EccDec_SM2Mode(char* encoded_C1string, char* encoded_C2string, big8w secretkey, char* message, int msglen);

#endif