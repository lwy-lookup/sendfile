#include "eccipccom.h"

void EccIBEInit()
{
  big8w one;
  memset(one.word, 0x00, BIG8W_BYTESIZE);
  one.word[0] = 1;

  memset(curve.b.word, 0x00, BIG8W_BYTESIZE);
  curve.b.word[0] = 0x05;

  uint32_t sm9_q[BIGNUMBER_SIZE_8WORD] = 
  {
    0xE351457D, 0xE56F9B27, 0x1A7AEEDB, 0x21F2934B,
    0xF58EC745, 0xD603AB4F, 0x02A3A6F1, 0xB6400000,
  };
  memcpy(curve.q.word, sm9_q, BIG8W_BYTESIZE);

  uint32_t sm9_N[BIGNUMBER_SIZE_8WORD] =
  {
    0xD69ECF25, 0xE56EE19C, 0x18EA8BEE, 0x49F2934B,
    0xF58EC744, 0xD603AB4F, 0x02A3A6F1, 0xB6400000,
  };
  memcpy(curve.N.word, sm9_N, BIG8W_BYTESIZE);

  uint32_t sm9_P_x[BIGNUMBER_SIZE_8WORD] =
  {
    0x7C66DDDD, 0xE8C4E481, 0x09DC3280, 0xE1E40869,
    0x487D01D6, 0xF5ED0704, 0x62BF718F, 0x93DE051D,
  };
  memcpy(P.x.word, sm9_P_x, BIG8W_BYTESIZE);

  uint32_t sm9_P_y[BIGNUMBER_SIZE_8WORD] =
  {
    0x0A3EA616, 0x0C464CD7, 0xFA602435, 0x1C1C00CB,
    0x5C395BBC, 0x63106512, 0x4F21E607, 0x21FE8DDA,
  };
  memcpy(P.y.word, sm9_P_y, BIG8W_BYTESIZE);

  uint32_t sm9_q_2k[BIGNUMBER_SIZE_8WORD] = 
  {
    0xb417e2d2, 0x27dea312, 0xae1a5d3f, 0x88f8105f,
    0xd6706e7b, 0xe479b522, 0x56f62fbd, 0x2ea795a6,
  };
  memcpy(q_2k.word, sm9_q_2k, BIG8W_BYTESIZE);

  uint32_t sm9_N_2k[BIGNUMBER_SIZE_8WORD] = 
  {
    0xcd750c35, 0x7598cd79, 0xbb6daeab, 0xe4a08110,
    0x7d78a1f9, 0xbfee4bae, 0x63695d0e, 0x8894f5d1,
  };
  memcpy(N_2k.word, sm9_N_2k, BIG8W_BYTESIZE);

}

void ServerInit_ECC()
{
  EccIBEInit();
  k1 = RandomNumGenerate();
  k2 = RandomNumGenerate();
  
  PubKey1 = G1pointMult(k1, P);

  PubKey2 = G1pointMult(k2, P);
}

void ProduceSecretKey(char* DeviceID, unsigned int IDlen, big8w* secretkey, G1point* publickey)
{
  unsigned char* string;
  unsigned char tmp[32];
  int i;

  string = (unsigned char*)(malloc(IDlen + 2));
  memset(string, 0x00, IDlen + 2);

  for (i = 0; i < IDlen; i++)
    string[i] = DeviceID[i];
  string[i] = 0x01;

  sm3(string, IDlen + 1, tmp);

  for (i = 1; i < BIGNUMBER_SIZE_8WORD + 1; i++) 
	secretkey->word[BIGNUMBER_SIZE_8WORD - i] = GETU32(tmp + 4 * (i - 1));

  *secretkey = Big8wMultMod(*secretkey, k1, curve.N);
  *secretkey = Big8wAddMod(*secretkey, k2, curve.N);

  *publickey = G1pointMult(*secretkey, P);
  free(string);
}

void GetPubKeyFromID(char* ID, unsigned int IDlen, G1point* pubkey)
{
  unsigned char* string;
  unsigned char tmp[32];
  int i;
  big8w temp;

  string = (unsigned char*)(malloc(IDlen + 2));
  memset(string, 0x00, IDlen + 2);

  for (i = 0; i < IDlen; i++)
    string[i] = ID[i];
  string[i] = 0x01;

  sm3(string, IDlen + 1, tmp);

  for (i = 1; i < BIGNUMBER_SIZE_8WORD + 1; i++) 
		temp.word[BIGNUMBER_SIZE_8WORD - i] = GETU32(tmp + 4 * (i - 1));
    
  *pubkey = G1pointMult(temp, PubKey1);

  *pubkey = G1pointAdd(*pubkey, PubKey2);
  free(string);
}
