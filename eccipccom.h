#ifndef ECCIPCCOM_h
#define ECCIPCCOM_h

#include <stdio.h>
#include <error.h>

#include "sm2.h"

G1point P, PubKey1, PubKey2;
big8w k1, k2;
big8w client_secretkey;

void EccIBEInit();
void ServerInit_ECC();
void ProduceSecretKey(char* DeviceID, unsigned int IDlen, big8w* secretkey, G1point* publickey);
void GetPubKeyFromID(char* ID, unsigned int IDlen, G1point* pubkey);

#endif
