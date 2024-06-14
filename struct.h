
#define ENC_LEN_MAX 60

#define BODY_LEN 500

#define LEN_MAX 20 //lunghezza massima del messaggio dal client



typedef struct _MSG //definiamo la struttura del messaggio value->client da cui ci è stato inviato il messaggio, tipo->contenuto del messaggio
{
    int value;
    char tipo[LEN_MAX];
} MSG;



typedef struct  _CREDENTIALS 
{

char email[LEN_MAX];
char username[LEN_MAX];
char password[LEN_MAX];

} CREDENTIALS;


typedef struct  _LOGIN_CONFIRMATION
{

char risposta[LEN_MAX];

} LOGIN_CONFIRMATION;


typedef struct _PUBKEY
{

char* buffer_pubKey[1190];

} PUBKEY;



typedef struct _CHALLENGE
{

int value;

} CHALLENGE;

typedef struct _HASH_ENC
{



unsigned char signature[390];
size_t signature_len;

} HASH_ENC;


typedef struct  _ENC_CREDENTIALS 
{

unsigned char enc_email[ENC_LEN_MAX];
unsigned char enc_username[ENC_LEN_MAX];
unsigned char enc_password[ENC_LEN_MAX];
int iv;

} ENC_CREDENTIALS;


typedef struct _CHOICE
{

unsigned char value[LEN_MAX];

} CHOICE;

typedef struct _ENC_CHOICE
{

unsigned char enc_value[LEN_MAX];

} ENC_CHOICE;




typedef struct  _POST
{

char title[LEN_MAX];
char body[BODY_LEN];

} POST;


typedef struct  _ENC_POST
{

char enc_title[LEN_MAX];
//char enc_author[LEN_MAX];
char enc_body[BODY_LEN];

} ENC_POST;



typedef struct _MESSAGES_TO_LIST
{
    char id[LEN_MAX];
    char username[BODY_LEN];
    char title[BODY_LEN];
    char msg[BODY_LEN];
} MESSAGES_TO_LIST;


typedef struct _ENC_MESSAGES_TO_LIST
{
    char enc_id[LEN_MAX];
    char enc_username[BODY_LEN];
    char enc_title[BODY_LEN];
    char enc_msg[BODY_LEN];
} ENC_MESSAGES_TO_LIST;
