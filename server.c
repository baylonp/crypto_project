#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h> 
#include <openssl/sha.h>

#include <netdb.h>  
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/dh.h>

#include <openssl/core_names.h>

#include <openssl/params.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

#include <openssl/ossl_typ.h>

//#include "security.h"
//#include "hash.h"
//#include "string.h"

#include "header/utility.h"
//#include "header/DH.h"


//#include "header/struct.h"
#include "header/dh_keygen.h"
#include "header/shared_secret.h"
#include"header/key_derivation.h"
#include "header/crypto_utils.h"

#define BUFFER_SIZE 4096
#define TAG_SIZE 16 // Dimensione del tag di autenticazione per AES-GCM (16 byte)
#define MAX_MESSAGES 200


int main(int argc, char *argv[]){

    int sock;
    struct sockaddr_in server, client;
    int lenght = sizeof(client);
    int current_sock;
    int porta = 10000;
    long int id =0;
    int logged_user = 0 ;


    MSG messaggio;

    CREDENTIALS credenziali;


    LOGIN_CONFIRMATION conferma;


    PUBKEY pubkey;


    CHALLENGE challenge;

    HASH_ENC struct_hash_enc;

    ENC_CREDENTIALS encrypted_credentials;

    CHOICE choice;
    
    ENC_CHOICE enc_choice;

    POST post;

    ENC_POST enc_post;

    MESSAGES_TO_LIST msg_to_list[MAX_MESSAGES];
    ENC_MESSAGES_TO_LIST enc_msg_to_list;
    /*
    AF_INET->specifica la famiglia di indirizzi o il dominio della socket (Address family-->IPV4)
    SOCK_STREAM->specifica il tipo di socket: in questo caso vogliamo mandare flussi di byte tra client e server--> connection oriented byte stream
    0->indica il protocollo che vogliamo utilizzare
    */


    sock = socket(AF_INET, SOCK_STREAM, 0); //inizializziamo una socket-> ritorna uin file descriptor se la creazione è andata a buon fine altrimenti 0 
    
    if (sock < 0) //controllo se è andata a buon fine
    {
        perror("socket error");
        exit(-1);
    }

    /*
    Creiamo il nostro server -> specifichiamo l'indirizzo e la porta sulla quale in nostro server starà girando
    Effettuiamo un bindig tra l'indirizzo del server che andremo a creare e la socket appena creata 
    */

    server.sin_family = AF_INET; //determiniamo che tipologia di address fmaily utilizzerà il nostro server
    server.sin_addr.s_addr = INADDR_ANY;//l'indirizzo sul quale girerà il nostro server-> 2 opzioni: 1-> specifchiamo noi l'indirizzo 2-> _ANY lasciamo scelgiere un indirizzo libero al momento di esecuzione 
    server.sin_port = htons(porta);//htons permette di convertire l'intero in byte ricordando l'ordinamento che sfrutta l'OS sul quale sta girando il server

    if(bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
    perror("Binding error");
    exit(-1);
    }

   //Questa funzione per il momento no ci è utilissima in quanto verificha semplicemente che c'è una socket e che il bindig sia stato
   //fatto correttamente. Ma il tutto è già stato controllato dall'if sopra nel bind.
 /*   int len = sizeof(server);
    if(getsockname(sock, (struct sockaddr *)&server, &len) < 0) //verifichiamo che la socket sia associata al nostro server
    {
        perror("Error");
        exit(-1);
    }
    */

    //Possiamo ora iniziare ad ascoltare connessioni provenienti dai client

    if(listen(sock, 3)<0)//i paramentri sono 1-> la socket che vogliamo utilizzare 2->numero massimo di connessioni che si possono mettere in coda nel nostro server
    { 
        perror("Listen error");
        exit(-1);
    }

    
    printf("Server attivo sulla porta %d, aspetto connessioni\n", ntohs(server.sin_port));
    while (1) // server rimarrà in attesa qui per le richiestra da parte dei client
    {
       
        current_sock = accept(sock,(struct sockaddr *)&client, (socklen_t *)&lenght);// args: 1->socket sulla quale ricevere 2-> client da cui arriva la richiesta 3->puintatore alla lunghezza del messaggio che arriva
        //current_sock conterrà il file descriptor sul cui il client avrà scritto

        printf("Connessione arrivata\n");
        

        if (current_sock < 0) 
        {
            perror("Accept error");
            exit(-1);
        }


        int pid = fork(); // creiamo un processo figlio per gestire la richiesta 
        printf("pid attuale %d\n", pid);

        if (pid < 0)
        {
            perror("Fork error");
            exit(-1);
        }
        
        /*
        se la fork ritorna 0 vuol dire che siamo nel processo figlio e gestiamo la richiesta
        quando viene fatta una fork, viene sdoppiata la memoria e quando il processo figlio finisce e quindi ci troviamo nel caso in cui
        pid > 0 chiudiamo la socket che non ci serve più
        */
        
        if (pid == 0) 
        {



                
///////////////////////DH PARAM GEN KEYS///////////

            EVP_PKEY* my_privkey = NULL;

            // Generate DH key pair
            if (generate_dh_key_pair(&my_privkey) != 0) {
                printf("Failed to generate DH key pair.\n");
                return -1;
            }

            // Write the public key to a file
            if (write_public_key_to_file(my_privkey, "ACCESSIBLE_TO_SERVER/server_pubKey_DH.pem") != 0) {
                printf("Failed to write public key to file.\n");
                EVP_PKEY_free(my_privkey);
                return -1;
            }

            // Free the private key
            //EVP_PKEY_free(my_privkey);  //ricordarsi di liberarla

  
 
//////////////////////FINE DH PARAM GEN KEYS ////////////////
           
          

////////////////////LEGGO CHIAVE PUBLICA DEL CLIENT DALLA SOCKET///////////////

            //leggo la public_key del client
            if (read(current_sock, &pubkey ,sizeof(pubkey)) < 0)
                {
                    perror("Read error\n");
                    exit(-1);
                }


           // printf("pubKey: %s\n", pubkey.buffer_pubKey);


            //mi salvo la pubKey del client in un file
            FILE* fPointer;
        
            // opening the file in read mode
            fPointer = fopen("ACCESSIBLE_TO_SERVER/client_pubKey_DH.pem", "w+");
        
            // checking if the file is opened successfully
            if (fPointer == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                return -1;
            }

            fprintf(fPointer, &pubkey.buffer_pubKey);

            fclose(fPointer);



            //adesso mi carico la chiave pubblica del client dal file pem 
            //in una struttura EVP_PKEY


            FILE* puntFile;
        
            // opening the file in read mode
            puntFile = fopen("ACCESSIBLE_TO_SERVER/client_pubKey_DH.pem", "r");
        
            // checking if the file is opened successfully
            if (puntFile == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                return -1;
            }

            EVP_PKEY* client_pub_key= NULL;
            client_pub_key = PEM_read_PUBKEY(puntFile,NULL, NULL, NULL);

            if (client_pub_key == NULL){

                printf("Errore nel caricamento della chiave pubblica del client");
            }


            fclose(puntFile);

            // EVP_PKEY_free(client_priv_key);

////////////////////FINE LEGGO CHIAVE PUBLICA DEL CLIENT DALLA SOCKET///////////////



///////////////////////////INVIO MIA CHIAVE PUBBLICA AL CLIENT////////////////


            // Leggo la chiave pubblica DH dal file e la salvo
        FILE* fileP;

        // Apro il file in modalità lettura
        fileP = fopen("ACCESSIBLE_TO_SERVER/server_pubKey_DH.pem", "r");

        // Controllo se il file è stato aperto correttamente
        if (fileP == NULL) {
            printf("The file is not opened. The program will now exit.");
            return -1;
        }


        fseek(fileP, 0, SEEK_END);

        long fileSize = ftell(fileP);
        fseek(fileP, 0, SEEK_SET);

        //printf("filesize= %ld" , fileSize);



        fread(pubkey.buffer_pubKey , 1, fileSize, fileP);
        pubkey.buffer_pubKey[fileSize] = '\0'; // Add null terminator to end of file




        // Invia la sua chiave pubblica  al client
        if (write(current_sock, &pubkey, sizeof(pubkey)) < 0) {
            perror("Send error");
            return -1;
        }



        //free(buffer_pkey);
        fclose(fileP);




        //EVP_PKEY_free(pubKey);

//////// OPERAZIONI HASH chiave publica DH server + FIRMA com chiave privata server

        const char* private_key_file = "chiavi_RSA_SERVER/server_private.pem";


        // Read private key
        EVP_PKEY* private_key = read_private_key(private_key_file);
        if (!private_key) {
            fprintf(stderr, "Failed to read private key\n");
            return 1;
        }


        // Sign the data
        unsigned char *signature;
        size_t signature_len;
        if (!sign_data(pubkey.buffer_pubKey, strlen(pubkey.buffer_pubKey), &signature, &signature_len, private_key)) {
            fprintf(stderr, "Error signing data\n");
            return 1;
        }

        /*
        // Print the signature (in hexadecimal )
        printf("Signature: ");
        for (size_t i = 0; i < signature_len; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");
        */

        memcpy(struct_hash_enc.signature, signature, signature_len);

        struct_hash_enc.signature_len = signature_len;
        

        free(signature);

 
        EVP_PKEY_free(private_key);


/////// FINE OPERAZIONI HASH chiave publica DH server + FIRMA com chiave privata server


        // Invia l'hash della chiave pubblica DH delserver cifrata con la private key delserver al client
        if (write(current_sock, &struct_hash_enc, sizeof(struct_hash_enc)) < 0) {
            perror("Send error");
            return -1;
        }




///////////////////////////FINE INVIO MIA CHIAVE PUBBLICA AL CLIENT////////////////


/////////////INIZIO DERIVAZIONE SECRET //////////////////////

    size_t secret_len;
    unsigned char* secret = derive_shared_secret(my_privkey, client_pub_key, &secret_len);
    if (!secret) {
        printf("Failed to derive shared secret.\n");
        return -1;
    }

    // free(secret); //ricordarsi di liberare il secret
            
    //printf("secret: %hhu \n", *secret);


/////////////FINE DERIVAZIONE SECRET //////////////////////







//////////////// DERIVAZIONE CHIAVE SEGRETA Kab/////////////////

//hashiamo il segreto--> viene fuori un hash a 256 bit, peroò il cifrario che utilizziamo è 
//AES a 128, quindi la chiave è più grnade della dimensione della chiave che accetta il cifrario
//AES
    //derivo la chiave di sessione Kab
    //unsigned char* K_ab = session_key(EVP_sha256(),EVP_aes_128_gcm(),secret,secret_len,key_len);
    
    // const EVP_MD* Hash_type = ;
     //const EVP_CIPHER* Cipher_type = ;

    //


    unsigned int key_len;
    unsigned char* k_ab = derive_aes_key(secret, secret_len, &key_len);
    if (!k_ab) {
        printf("Failed to derive AES key.\n");
        free(secret);
        return -1;
    }
    //free(k_ab);
    free(secret);
        //ricordarsi di fare la free del k_ab
    //printf("k_ab: %hhu \n", full_k_ab);
  
    //sha 256 genera 256 bit di chiave, sono troppi per l'aes a 128 bit--> quindi tronchiamo



////////////////FINE DERIVAZIONE CHIAVE SEGERTA Kab/////////////////




            //leggo la scelta fatta
            if (read(current_sock, &choice ,sizeof(choice)) < 0)
                {
                    perror("Read error\n");
                    exit(-1);
                }





            unsigned char tag[TAG_SIZE];
            

            //leggo le credenziali cifrate arrivate
            if (read(current_sock, &encrypted_credentials ,sizeof(encrypted_credentials)) < 0)
                {
                    perror("Read error\n");
                    exit(-1);
                }


            unsigned char* iv;
            iv = convertNumberToString(encrypted_credentials.iv);
        

            

            //decifro l'username
            int plaintext_username_len;
            unsigned char plaintext_username[128]; 
            plaintext_username_len = decrypt_data(encrypted_credentials.enc_username, sizeof(encrypted_credentials.enc_username), k_ab, iv, plaintext_username, tag  );
            //printf("Credentials: \n Username plaintext_username : %s\n ", plaintext_username);

            strcpy(credenziali.username,plaintext_username);

            

            

            

            //decifro l'email
            int plaintext_email_len;
            unsigned char plaintext_email[256]; 
            plaintext_email_len = decrypt_data(encrypted_credentials.enc_email, sizeof(encrypted_credentials.enc_email), k_ab, iv, plaintext_email , tag);
            
            //printf("Credentials: \n Email plaintext_email : %s ", plaintext_email);
            strcpy(credenziali.email,plaintext_email);

            //printf(" mail from struct: %s ", &credenziali.email);
            

            

            //decifro la password
            int plaintext_password_len;
            unsigned char plaintext_password[256]; 
            plaintext_password_len = decrypt_data(encrypted_credentials.enc_password, sizeof(encrypted_credentials.enc_password), k_ab, iv, plaintext_password, tag  );
           
            strcpy(credenziali.password, plaintext_password);


            


            //printf("Credentials: \n Email: %s ", &credenziali.email);
           // printf("Credentials: \n Email: %s \n  Username: %s \n Password: %s \n ", &credenziali.email, &credenziali.username, &credenziali.password);

            //unsigned char* email_string = "vuoto";


            if (strcmp(choice.value,"1") == 0){ //login


                    //printf(" user from struct: %s \n", &credenziali.username);
                    //printf(" password from struct: %s \n", &credenziali.password);


                    //funzione di login

                    int logged_user=login(credenziali.email, credenziali.username, credenziali.password);

                    if(logged_user == -2){



                        // ritorna al client l'errore sulla password
                        strcpy(conferma.risposta,"-2");

                        if (write(current_sock, &conferma, sizeof(conferma)) < 0) {
                            perror("Send error");
                            return -1;
                        }

                        printf("Wrong Password :( \n");

                    }else if(logged_user == -1){


                        // ritorna al client l'errore sull'utente non trovato
                        strcpy(conferma.risposta,"-1");

                        if (write(current_sock, &conferma, sizeof(conferma)) < 0) {
                            perror("Send error");
                            return -1;
                        }

                        printf("User not found, you need to register");

                    }else{



                            // conferma al client di essersi loggato
                            strcpy(conferma.risposta,"1");;

                            if (write(current_sock, &conferma, sizeof(conferma)) < 0) {
                                perror("Send error");
                                return -1;
                            }

                            int ctrl = 0;
                            while(1){

                                ctrl = 0;
                                //leggo la scelta fatta dopo cheil client si è loggato
                                if (read(current_sock, &choice ,sizeof(choice)) < 0)
                                {
                                    perror("Read error\n");
                                    exit(-1);
                                }

                                if(strcmp(choice.value,"1") == 0){  //make a post

                                    ctrl = 1;

                                    //leggo il messaggio cifrato che l'utente ha scritto
                                    if (read(current_sock, &enc_post ,sizeof(enc_post)) < 0)
                                    {
                                        perror("Read error\n");
                                        exit(-1);
                                    }


                                    printf("ci sono\n");


                                    //decifro il titolo del messaggio

                                    int plaintext_title_len;
                                    unsigned char plaintext_title[LEN_MAX]; 
                                    plaintext_title_len = decrypt_data(enc_post.enc_title, sizeof(enc_post.enc_title), k_ab, iv, plaintext_title, tag  );

                                    strcpy(post.title,plaintext_title);

                                    //printf(" titolo: %s", post.title);

                                    //decifro il body

                                    int plaintext_body_len;
                                    unsigned char plaintext_body[BODY_LEN]; 
                                    plaintext_body_len = decrypt_data(enc_post.enc_body, sizeof(enc_post.enc_body), k_ab, iv, plaintext_body, tag  );

                                    strcpy(post.body,plaintext_body);


                                    //printf(" %s ha scritto \n Titolo: %s \n", credenziali.username, post.title);
                                    //printf(" %s ", post.body);

                                    long int msg_id = 0;
                                    if(add_to_db_of_messages(&msg_id, credenziali.username, post.title, post.body) < 0){

                                        printf("Error loading messages in db!");

                                        return 0;

                                    }


                                    



                                }else if(strcmp(choice.value,"2") == 0){ //listare i messaggi

                                        

                                        int value= 0;
                                        value = get_number_of_messages();
                                        //value = value -1;
                                        //char buf[LEN_MAX];

                                        strcpy(choice.value, convertNumberToString(value)); //abbiamo il valore della scelta nella struttura
                                        

                                        //printf("numero di messaggi totali =  %d\n", choice.value);
                                        //printf("sono in choice 2");


                                        //cifro il numero di messaggi totali
                                        int ciphertext_num_msgs_len;
                                        unsigned char ciphertext_num_msgs[64]; 
                                        ciphertext_num_msgs_len = encrypt_data(choice.value, sizeof(choice.value),k_ab , iv, ciphertext_num_msgs , tag);
                            
                                        memcpy(enc_choice.enc_value,ciphertext_num_msgs,ciphertext_num_msgs_len);


                                    
                                        
                                        
                                        //Scrivo nella socket il numero totale di messaggi nel DB
                                        if (write(current_sock, &enc_choice, sizeof(enc_choice)) < 0) {
                                            perror("Num msgs Send error");
                                            return -1;
                                        }
                                            
                                            
                                            
                                        // c'è da legger dalla socket il numero di messaggi che l'utente ha scelto di leggere


                                        //leggo il numero di messaggi da stampare cifrato
                                        if (read(current_sock, &enc_choice ,sizeof(enc_choice)) < 0)
                                        {
                                            perror("Read error\n");
                                            exit(-1);
                                        }

                                        //decifro il num di messaggi da stampare totali
                                        int plaintext_num_mgs_to_print_len;
                                        unsigned char plaintext_num_msgs_to_print[256]; 
                                        plaintext_num_mgs_to_print_len = decrypt_data(enc_choice.enc_value, sizeof(enc_choice.enc_value), k_ab, iv, plaintext_num_msgs_to_print, tag  );

                                        strcpy(choice.value, plaintext_num_msgs_to_print ); //mettiamo il numero di messaggi da stampare in choice.value, è una stringa



                                ////////////////////INIZIO LE OPERAZIONI PER MANDARE IL NUMERO DI MESSAGGI RICHIESTI//////////
                                // Apri il file CSV in modalità di lettura
                                        FILE *file = fopen("messages_db.csv", "r");
                                        if (file == NULL) {
                                            perror("Errore durante l'apertura del file");
                                            exit(EXIT_FAILURE);
                                        }

                                        // Carica i dati dal file CSV in una struttura dati
                                        
                                        int num_msgs = 0;
                                        char line[MAX_LINE_LENGTH];


                                        while (fgets(line, sizeof(line), file) != NULL && num_msgs < atoi(choice.value)) {
                                            // Analizza la riga per estrarre i dati dell'utente
                                            char *token = strtok(line, ",");  //strok() ha già un puntatore al token successivo, ecco perchè nelle chiamate successive si mette NULL

                                            
                                            strcpy(msg_to_list[num_msgs].id, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_msgs].username, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_msgs].title, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_msgs].msg, token);

                                            num_msgs++;
                                        }

                                            fclose(file);


                                        for(int i = 0; i < num_msgs; i++){
                                        

                                                //cifro l'id di chi hainviato il messaggio 
                                                int ciphertext_id_len;
                                                unsigned char ciphertext_id[128]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_id_len = encrypt_data(msg_to_list[i].id, sizeof(msg_to_list[i].id),k_ab , iv, ciphertext_id , tag);

                                                memcpy(enc_msg_to_list.enc_id, ciphertext_id, ciphertext_id_len);



                                                //cifro username di chi ha inviato il messaggio 
                                                int ciphertext_username_len;
                                                unsigned char ciphertext_username[128]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_username_len = encrypt_data(msg_to_list[i].username, sizeof(msg_to_list[i].username),k_ab , iv, ciphertext_username , tag);

                                                memcpy(enc_msg_to_list.enc_username, ciphertext_username, ciphertext_username_len);


                                                //cifro il titolo del messaggio  
                                                int ciphertext_title_len;
                                                unsigned char ciphertext_title[BODY_LEN]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_title_len = encrypt_data(msg_to_list[i].title, sizeof(msg_to_list[i].title),k_ab , iv, ciphertext_title , tag);

                                                memcpy(enc_msg_to_list.enc_title, ciphertext_title, ciphertext_title_len);


                                                //cifro il  messaggio  
                                                int ciphertext_msg_len;
                                                unsigned char ciphertext_msg[BODY_LEN]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_msg_len = encrypt_data(msg_to_list[i].msg, sizeof(msg_to_list[i].msg),k_ab , iv, ciphertext_msg , tag);

                                                memcpy(enc_msg_to_list.enc_msg, ciphertext_msg, ciphertext_msg_len);


                                                //Scrivo nella socket il  totale di messaggi nel DB
                                                if (write(current_sock, &enc_msg_to_list, sizeof(enc_msg_to_list)) < 0) {
                                                    perror(" msgs Send error in for");
                                                    return -1;
                                                }
                                        }


                                        //strcpy(choice.value,"0");
        ////////////////////////////////////////

                                }else if (strcmp(choice.value,"3") == 0){

                                        ctrl = 1;

                                    // Apri il file CSV in modalità di lettura
                                        FILE *puntator = fopen("messages_db.csv", "r");
                                        if (puntator == NULL) {
                                            perror("Errore durante l'apertura del file");
                                            exit(EXIT_FAILURE);
                                        }

                                        // Carica i dati dal file CSV in una struttura dati
                                        
                                        int num_msgs = 0;
                                        char lines[MAX_LINE_LENGTH];


                                        ////////////CALCOLO ID ///////////////////

                                        long current_pos = ftell(puntator); // Salva la posizione corrente nel file
                                        rewind(puntator);

                                        // Conta il numero di righe nel file
                                            
                                            char c;
                                            while ((c = fgetc(puntator)) != EOF) {
                                                if (c == '\n') {
                                                    num_msgs ++;
                                                }
                                            }

                                        fseek(puntator, current_pos, SEEK_SET); // Ritorna alla posizione corrente nel file

                                        ////////////////////////////////////

                                        fclose(puntator);

                                        char* num_msgs_stringa;

                                        num_msgs_stringa = convertNumberToString(num_msgs);

                                        //printf("numero mex: %s", num_msgs_stringa);

                                        strcpy(choice.value,num_msgs_stringa);

                                        //cifro il numero di messaggi totali
                                        int ciphertext_num_msgs_len;
                                        unsigned char ciphertext_num_msgs[64]; 
                                        ciphertext_num_msgs_len = encrypt_data(choice.value, sizeof(choice.value),k_ab , iv, ciphertext_num_msgs , tag);
                            
                                        memcpy(enc_choice.enc_value,ciphertext_num_msgs,ciphertext_num_msgs_len);
                                        
                                        //Scrivo nella socket il numero totale di messaggi nel DB
                                        if (write(current_sock, &enc_choice, sizeof(enc_choice)) < 0) {
                                            perror("Num msgs Send error");
                                            return -1;
                                        }
            



                                        //leggo l'id del messaggio che l'utente vuole salvarsi
                                        if (read(current_sock, &enc_choice ,sizeof(enc_choice)) < 0)
                                        {
                                            perror("Read error\n");
                                            exit(-1);
                                        }

                                        //printf("enc choice: %s", enc_choice.enc_value);


                                        //decifro il num di messaggi da stampare totali
                                        int plaintext_msg_id_to_save_len;
                                        unsigned char plaintext_msg_id_to_save[256]; 
                                        plaintext_msg_id_to_save_len = decrypt_data(enc_choice.enc_value, sizeof(enc_choice.enc_value), k_ab, iv, plaintext_msg_id_to_save, tag  );

                                        strcpy(choice.value, plaintext_msg_id_to_save ); //mettiamo il numero di messaggi da stampare in choice.value, è una stringa


                                        int msg_id_to_save = atoi(choice.value); //così è intero

                                        //printf("id mex: %d", msg_id_to_save);


                                        // Apri il file CSV in modalità di lettura
                                        FILE *file = fopen("messages_db.csv", "r");
                                        if (file == NULL) {
                                            perror("Errore durante l'apertura del file");
                                            exit(EXIT_FAILURE);
                                        }

                                        // Carica i dati dal file CSV in una struttura dati
                                        
                                        int num_messaggi = 0;
                                        char line[MAX_LINE_LENGTH];

                                        

                                        while (fgets(line, sizeof(line), file) != NULL && num_messaggi <= msg_id_to_save) {

                                            

                                            // Analizza la riga per estrarre i dati dell'utente
                                            char *token = strtok(line, ",");  //strok() ha già un puntatore al token successivo, ecco perchè nelle chiamate successive si mette NULL

                                            
                                            strcpy(msg_to_list[num_messaggi].id, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_messaggi].username, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_messaggi].title, token);

                                            token = strtok(NULL, ",");
                                            strcpy(msg_to_list[num_messaggi].msg, token);

                                            num_messaggi++;
                                        }

                                            fclose(file);


                                        for(int i = 0; i < num_messaggi; i++){  

                                            


                                            int num = atoi(msg_to_list[i].id);

                                           

                                            if(num == msg_id_to_save ) {


                                                
                                                
                                                //cifro username di chi ha inviato il messaggio 
                                                int ciphertext_username_len;
                                                unsigned char ciphertext_username[128]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_username_len = encrypt_data(msg_to_list[i].username, sizeof(msg_to_list[i].username),k_ab , iv, ciphertext_username , tag);

                                                memcpy(enc_msg_to_list.enc_username, ciphertext_username, ciphertext_username_len);


                                                //cifro il titolo del messaggio  
                                                int ciphertext_title_len;
                                                unsigned char ciphertext_title[BODY_LEN]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_title_len = encrypt_data(msg_to_list[i].title, sizeof(msg_to_list[i].title),k_ab , iv, ciphertext_title , tag);

                                                memcpy(enc_msg_to_list.enc_title, ciphertext_title, ciphertext_title_len);


                                                //cifro il  messaggio  
                                                int ciphertext_msg_len;
                                                unsigned char ciphertext_msg[BODY_LEN]; //il controllo sull'username è fatto nel regex in utility
                                                ciphertext_msg_len = encrypt_data(msg_to_list[i].msg, sizeof(msg_to_list[i].msg),k_ab , iv, ciphertext_msg , tag);

                                                memcpy(enc_msg_to_list.enc_msg, ciphertext_msg, ciphertext_msg_len);


                                                //Scrivo nella socket il  totale di messaggi nel DB
                                                if (write(current_sock, &enc_msg_to_list, sizeof(enc_msg_to_list)) < 0) {
                                                    perror(" msgs Send error in for");
                                                    return 0;
                                                }
                                                

                                            }


                                        }  




                                }else if(strcmp(choice.value,"4") == 0){

                                    ctrl = 1;

                                    printf("User logged out\n");
                                    close(current_sock);

                                }
                                else{

                                    ctrl = 1;

                                    printf("Wrong choice (server)\n");

                                }



                        }   

                        
                    }

            }else {   // REGISTRAZIONE UTENTE

                    //printf(" user from struct: %s \n", &credenziali.username);
                    //printf(" password from struct: %s\n ", &credenziali.password);
                    //printf(" email from struct: %s \n", &credenziali.email);



                int random_challenge;
                random_challenge = challenge_fun(credenziali.username, credenziali.email);
  
                //leggo la challenge 
                if (read(current_sock, &challenge ,sizeof(challenge)) < 0)
                    {
                        perror("Read error\n");
                        exit(-1);
                    }

                int ret_reg = registration(&id, credenziali.email,credenziali.username,credenziali.password, challenge.value, random_challenge);
                unsigned char* ret_reg_string;
                
                ret_reg_string = convertNumberToString(ret_reg);



                if( ret_reg < 0 ){

                    //error.risposta= -1;
                    //invia al client il -1 
                   // write(current_sock,&error,sizeof(error));




                        printf("Registration failed, try again.\n");

                        


                        //cifro il valore di risposta da segnalare al client
                        int ciphertext_reg_confirmation_len;
                        unsigned char ciphertext_reg_confirmation[20]; 
                        //strcpy(ciphertext_reg_confirmation, ret_reg_string);
                        ciphertext_reg_confirmation_len = encrypt_data(ret_reg_string, sizeof(ret_reg_string),k_ab , iv, ciphertext_reg_confirmation , tag);
            
                        memcpy(enc_choice.enc_value, ciphertext_reg_confirmation, ciphertext_reg_confirmation_len);

                        //printf("enc choice: %s", enc_choice.enc_value);


                       
                        //printf("reg conf decifrato in loco: %s\n", choice.value);





                        //Scrivo nella socket il valore del register confirmation ( se la registrazione è andata a buon fine o no )
                        if (write(current_sock, &enc_choice, sizeof(enc_choice)) < 0) {
                            perror(" Send error");
                            return -1;
                        }



                }else{

                        //cifro il valore di risposta da segnalare al client
                        int ciphertext_reg_confirmation_len;
                        unsigned char ciphertext_reg_confirmation[10];
                        strcpy(ciphertext_reg_confirmation, ret_reg_string); 
                        ciphertext_reg_confirmation_len = encrypt_data(ret_reg_string, sizeof(ret_reg_string),k_ab , iv, ciphertext_reg_confirmation , tag);
            
                        memcpy(enc_choice.enc_value,ciphertext_reg_confirmation,ciphertext_reg_confirmation_len);

                        //Scrivo nella socket il valore del register confirmation ( se la registrazione è andata a buon fine o no )
                        if (write(current_sock, &enc_choice, sizeof(enc_choice)) < 0) {
                            perror(" Send error");
                            return -1;
                        }


                }

            }



            close(current_sock);
            exit(0);
            
        }

        if (pid > 0)//siamo nel processo padre (quindi l'effettivo server), chiudiamo la socket e torniamo in accettazione delle nuove richieste
        {
            close(current_sock);
        }
        
        
    }

}