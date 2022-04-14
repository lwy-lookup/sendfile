#include "sm2.h"

void SM2GetZ(char* ID, int IDlen, big8w a, big8w b, G1point* P, G1point* pubkey, unsigned char* Z)
{
    unsigned char* Zstring;
    int Zstringlen;
    int i;

    Zstringlen = BIG8W_BYTESIZE * 6 + IDlen + 2;
    Zstring = (unsigned char*)(malloc(Zstringlen));

    Zstring[0] = IDlen >> 2;
    Zstring[1] = (IDlen & 0x3) << 3;

    for (i = 0; i < IDlen; i++)
        Zstring[i + 2] = ID[i];
    
    Big8wIntou8string(&a, Zstring, IDlen + 2);
    Big8wIntou8string(&b, Zstring, IDlen + 2 + BIG8W_BYTESIZE);
    Big8wIntou8string(&P->x, Zstring, IDlen + 2 + BIG8W_BYTESIZE * 2);
    Big8wIntou8string(&P->y, Zstring, IDlen + 2 + BIG8W_BYTESIZE * 3);
    Big8wIntou8string(&pubkey->x, Zstring, IDlen + 2 + BIG8W_BYTESIZE * 4);
    Big8wIntou8string(&pubkey->y, Zstring, IDlen + 2 + BIG8W_BYTESIZE * 5);

    sm3(Zstring, Zstringlen, Z);

    free(Zstring);
}

void SM2Sign(char* message, int msglen, char* ID_self, int IDlen, big8w a, big8w b, 
                G1point* P, G1point* pubkey, big8w secretkey, unsigned char* signature)
{
    unsigned char* Mstring;
    unsigned char e_u8string[SM3OUT_32BYTES] = {0};

    int i;

    big8w e, k, r, s;
    G1point temp;

    Mstring = (unsigned char*)(malloc(msglen + SM3OUT_32BYTES));
    memset(Mstring, 0x00, msglen + SM3OUT_32BYTES);

    SM2GetZ(ID_self, IDlen, a, b, P, pubkey, Mstring);

    for (i = 0; i < msglen; i++)
        Mstring[i + SM3OUT_32BYTES] = message[i];
    
    sm3(Mstring, msglen + SM3OUT_32BYTES, e_u8string);

    U8StringToBig8w(e_u8string, &e);
    // printf("below is e in SM2Sign:\n");
    // Big8wPrint(&e);

    do{
        k = RandomNumGenerate();

        temp = G1pointMult(k, *P);

        r = Big8wAddMod(e, temp.x, curve.N);
        e = secretkey;

        i = 0;
        while(e.word[i] == 0xffffffff)
            i++;

        e.word[i]++;

        while (i)
            e.word[--i] = 0;

        e = Big8wReverse(e, curve.N);

        s = Big8wMultMod(r, secretkey, curve.N);
        s = Big8wMinusMod(k, s, curve.N);

        s = Big8wMultMod(s, e, curve.N);

        k = Big8wAddMod(r, k, curve.N);

    }while(Big8wIsZero(&r) || Big8wIsZero(&k) || Big8wIsZero(&s));

    Big8wIntou8string(&r, signature, 0);
    Big8wIntou8string(&s, signature, BIG8W_BYTESIZE);

    // printf("below is r in SM2Sign:\n");
    // Big8wPrint(&r);
    // printf("below is s in SM2Sign:\n");
    // Big8wPrint(&s);

    free(Mstring);
}

bool SM2VerifySign(char* message, int msglen, char* ID_self, int IDlen, big8w a, big8w b, 
                G1point* P, G1point* pubkey, unsigned char* signature)
{
    big8w r, s, t, e;
    G1point temp;
    unsigned char* Mstring;
    unsigned char e_u8string[SM3OUT_32BYTES] = {0};
    unsigned char *Zstring;
    int Zstringlen;
    int i;

    Mstring = (unsigned char*)(malloc(msglen + SM3OUT_32BYTES));
    memset(Mstring, 0x00, msglen + SM3OUT_32BYTES);

    SM2GetZ(ID_self, IDlen, a, b, P, pubkey, Mstring);

    for (i = 0; i < msglen; i++)
        Mstring[i + SM3OUT_32BYTES] = message[i];
    
    sm3(Mstring, msglen + SM3OUT_32BYTES, e_u8string);

    U8StringToBig8w(e_u8string, &e);
    U8StringToBig8w(signature, &r);
    U8StringToBig8w(signature + BIG8W_BYTESIZE, &s);

    // printf("below is e in SM2VerifySign:\n");
    // Big8wPrint(&e);
    // printf("below is r in SM2VerifySign:\n");
    // Big8wPrint(&r);
    // printf("below is s in SM2VerifySign:\n");
    // Big8wPrint(&s);

    t = Big8wAddMod(r, s, curve.N);
    if (Big8wIsZero(&t)){
        perror("SM2 signature verify error, r + s = 0 mod N\n");
        free(Mstring);
        return false;
    }

    temp = G1pointMult(s, *P);
    temp = G1pointAdd(temp, G1pointMult(t, *pubkey));

    e = Big8wAddMod(e, temp.x, curve.N);
    if (!Big8wEqual(&e, &r)){
        perror("SM2 signature verify error, r' != r\n");
        free(Mstring);
        return false;
    }

    free(Mstring);
    return true;

}

// bool SM2KeyExchangeProduceData()
// {

// }

// bool SM2KeyExchangeProduceKey()
// {

// }

// bool SM2KeyExchangeVerifyKey()
// {

// }

bool EccEnc_SM2EncMode(char* message, int msglen, G1point pubkey_counterpart, char* encoded_C1string, char* encoded_C2string)
{
  big8w k;
  G1point C1, temp;
//   char *encoded_C2string;
//   char encoded_C1string[128] = {0};
  unsigned char* t;
  int tlen;
  int i;
  unsigned char temp_u8string[BIG8W_BYTESIZE * 2] = {0};

  tlen = ((msglen >> 5) + 1) * SM3OUT_32BYTES;
  t = (unsigned char*)(malloc(tlen));
  memset(t, 0x00, tlen);

//   encoded_C2string = (char*)(malloc(msglen * 2));
//   memset(encoded_C2string, 0x00, msglen * 2);

  k = RandomNumGenerate();
  C1 = G1pointMult(k, P);
  Big8wIntou8string(&C1.x, temp_u8string, 0);
  Big8wIntou8string(&C1.y, temp_u8string, BIG8W_BYTESIZE);
  Base64Encode(temp_u8string, BIG8W_BYTESIZE * 2, encoded_C1string);

  temp = G1pointMult(k, pubkey_counterpart);
  Big8wIntou8string(&temp.x, temp_u8string, 0);
  Big8wIntou8string(&temp.y, temp_u8string, BIG8W_BYTESIZE);

  KDF(temp_u8string, BIG8W_BYTESIZE * 2, msglen * 8, t);

  for (i = 0; i < msglen; i++)
    t[i] ^= message[i];

  Base64Encode(t, msglen, encoded_C2string);
  free(t);
  // printf("encoded_C2string in EccEnc_SM2EncMode:\n%s\n", encoded_C2string);

  //C3

}

bool EccDec_SM2Mode(char* encoded_C1string, char* encoded_C2string, big8w secretkey, char* message, int msglen)
{
  G1point C1, temp;
//   char* message;
//   char encoded_C1string[128] = {0};
//   char *encoded_C2string;
  unsigned char temp_u8string[BIG8W_BYTESIZE * 2] = {0};
  unsigned char* t;
//   char msglen_str[8] = {0};
  unsigned char *C2_u8string;
  int tlen;
  int i;

//   msglen = atoi(msglen_str);

//   message = (char*)(malloc(msglen + 1));
//   memset(message, 0x00, msglen + 1);

  tlen = ((msglen >> 5) + 1) * SM3OUT_32BYTES;
  t = (unsigned char*)(malloc(tlen));
  memset(t, 0x00, tlen);

//   encoded_C2string = (char *)(malloc(msglen * 2));
//   memset(encoded_C2string, 0x00, msglen * 2);

  C2_u8string = (unsigned char*)(malloc(msglen * 2));
  memset(C2_u8string, 0x00, msglen * 2);

  // printf("encoded_C1string in EccDec_SM2Mode:\n%s\n", encoded_C1string);

  Base64Decode(encoded_C1string, 88, temp_u8string);
  U8StringToBig8w(temp_u8string, &C1.x);
  U8StringToBig8w(temp_u8string + BIG8W_BYTESIZE, &C1.y);

  // printf("below is C1 in EccEnc_SM2DecMode\n");
  // G1pointPrint(&C1);

  if (!PointInG1(C1)){
    perror("error, C1 is not in G1, in function EccDec_SM2Mode\n");
    free(t);
    free(encoded_C2string);
    free(C2_u8string);
    return false;
  }

  temp = G1pointMult(secretkey, C1);
  Big8wIntou8string(&temp.x, temp_u8string, 0);
  Big8wIntou8string(&temp.y, temp_u8string, BIG8W_BYTESIZE);

  KDF(temp_u8string, BIG8W_BYTESIZE * 2, msglen * 8, t);

  // printf("encoded_C2string in EccDec_SM2Mode:\n%s\n", encoded_C2string);
  Base64Decode(encoded_C2string, strlen(encoded_C2string), C2_u8string);
  
  for (i = 0; i < msglen; i++)
    message[i] = t[i] ^ C2_u8string[i];

  free(t);
  free(C2_u8string);

  return true;
}
