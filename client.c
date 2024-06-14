#include <unistd.h>
#include<string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
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
#include "header/utility.h"


#include "header/dh_keygen.h"
#include "header/shared_secret.h"
#include "header/key_derivation.h"

#include "header/crypto_utils.h"

//#include "security.h"

#define SERVER_PORT 10000




int main(int argc, char *argv[]){



    int clien_fd;
    struct sockaddr_in server_address;
    struct hostent *hp;
    MSG messaggio;

    CREDENTIALS credenziali;

    PUBKEY pub_key;

    HASH_ENC struct_hash_enc;

    CHALLENGE input_challenge;

    ENC_CREDENTIALS encrypted_credentials;


    LOGIN_CONFIRMATION conferma;

    CHOICE choice;

    ENC_CHOICE enc_choice;

    POST post;

    ENC_POST enc_post;

    MESSAGES_TO_LIST msg_to_list;

    ENC_MESSAGES_TO_LIST enc_msg_to_list;



    //DH_KEYS dh_keys;

    //ERROR error;




    clien_fd = socket(AF_INET,SOCK_STREAM,0);
    
    if (clien_fd<0)
    {
        perror("Socket error");
        exit(-1);
    }
    
    server_address.sin_family = AF_INET; //tipologia di address family server
    server_address.sin_port = htons(SERVER_PORT);//porta del server->RICORDA htons serve per conversione intero->byte mantenendo l'ordinamento del sistema operativo (funzione inversa nthos)

    
    hp = gethostbyname("localhost");

    if (hp<0)
    {
       perror("Error localhost");
       exit(-1);
    }

    /*
    memcpy->non abbiamo copiato l'indirizzo che abbiamo trovato nel localhost nel server address, senza questa funzione ci stiamo connettendo ad un 
    indirizzo senza aver specificato l'effettivo indirizzo su cui connetterci. Fino a questo punto abbiamo solo verificato che giri un server su
    localhost
    */
    memcpy((char *)&server_address.sin_addr, (char *)hp->h_addr, hp->h_length);

    if (connect(clien_fd,(struct sockaddr *)&server_address, sizeof(server_address))<0)
    {
        perror("Connect error");
        exit(-1);
    }

    //printf("Siamo connessi al server\n");



 

  //  while(1){


///////////////////////DH PARAM GEN KEYS///////////

 //generaz le chiavi per il client e scrive la chiave pubblica del client dentro al file ACCESSIBLE_TO_CLIENTS/client_pubKey_DH.pem
    EVP_PKEY* my_privkey = NULL;

    // Generate DH key pair
    if (generate_dh_key_pair(&my_privkey) != 0) {
        printf("Failed to generate DH key pair.\n");
        return -1;
    }

    // Write the public key to a file
    if (write_public_key_to_file(my_privkey, "ACCESSIBLE_TO_CLIENTS/client_pubKey_DH.pem") != 0) {
        printf("Failed to write public key to file.\n");
        EVP_PKEY_free(my_privkey);
        return -1;
    }

    // Free the private key
    //EVP_PKEY_free(my_privkey);  //ricordarsi di liberarla



//////////////////////FINE DH PARAM GEN KEYS ////////////////




////////////////LEGGO CHIAVE PUBBLICA DAL FILE E INVIO AL SERVER////////////////
    



        // Leggo la chiave pubblica DH dal file e la salvo
    FILE* fileP;

    // Apro il file in modalità lettura
    fileP = fopen("ACCESSIBLE_TO_CLIENTS/client_pubKey_DH.pem", "r");

    // Controllo se il file è stato aperto correttamente
    if (fileP == NULL) {
        printf("The file is not opened. The program will now exit.");
        return -1;
    }


    fseek(fileP, 0, SEEK_END);

    long fileSize = ftell(fileP);
    fseek(fileP, 0, SEEK_SET);




    fread(pub_key.buffer_pubKey , 1, fileSize, fileP);
    pub_key.buffer_pubKey[fileSize] = '\0'; // Add null terminator to end of file



/////////////////////////////



    // Invia la sua chiave pubblica  al server
    if (write(clien_fd, &pub_key, sizeof(pub_key)) < 0) {
        perror("Send error");
        return -1;
    }



    //free(buffer_pkey);
    fclose(fileP);




 //EVP_PKEY_free( pubKey);

 ////////////////FINE LEGGO CHIAVE PUBBLICA DAL FILE E INVIO AL SERVER////////////////
    


/////////////// LEGGO CHIAVE PUBBLICA SERVER DA SOCKET ////////////////

            //leggo la public_key del server
            if (read(clien_fd, &pub_key ,sizeof(pub_key)) < 0)
                {
                    perror("Read error\n");
                    exit(-1);
                }
            // printf("pubKey: %s", pubkey.buffer_client_pubKey);


    //////// LEGGO L'HASH CIFRATO E LO DECIFRO CON la chiave pubblica RSA del server  e poi calcolo l'hashpure io e controllo che siano uguali

            //leggo la chiave pubblica RSA del server da file
            const char* public_key_file = "ACCESSIBLE_TO_CLIENTS/server_pubkey_RSA.pem";

            EVP_PKEY* public_key_RSA = read_public_key(public_key_file);
            if (!public_key_RSA) {
                fprintf(stderr, "Failed to read public key\n");

                return 1;
            }

            //leggo l'hash della public Key DH firmata dal server
            if (read(clien_fd, &struct_hash_enc ,sizeof(struct_hash_enc)) < 0)
                {
                    perror("Read error\n");
                    exit(-1);
                }


            int verification_result = verify_signature(pub_key.buffer_pubKey, strlen(pub_key.buffer_pubKey), struct_hash_enc.signature, struct_hash_enc.signature_len, public_key_RSA);

            if (verification_result != 1) {
                printf("Signature is Invalid, possible MiTM\n");
                return 0;
            }else{

                printf(ANSI_COLOR_GREEN "--->Signature is valid" ANSI_COLOR_RESET "\n");

            }


            // Clean up

            EVP_PKEY_free(public_key_RSA);


    ////////FINE  LEGGO L'HASH CIFRATO E LO DECIFRO CON la chiave pubblica RSA del server  e poi calcolo l'hashpure io e controllo che siano uguali


            //mi salvo la pubKey del server in un file
            FILE* fPointer;
        
            // opening the file in read mode
            fPointer = fopen("ACCESSIBLE_TO_CLIENTS/server_pubKey_DH.pem", "w+");
        
            // checking if the file is opened successfully
            if (fPointer == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                return -1;
            }

            fprintf(fPointer, &pub_key.buffer_pubKey);

            fclose(fPointer);



            //adesso mi carico la chiave pubblica del server dal file pem 
            //in un astruttura EVP_PKEY


            FILE* puntFile;
        
            // opening the file in read mode
            puntFile = fopen("ACCESSIBLE_TO_CLIENTS/server_pubKey_DH.pem", "r");
        
            // checking if the file is opened successfully
            if (puntFile == NULL) {
                printf("The file is not opened. The program will "
                    "now exit.");
                return -1;
            }

            EVP_PKEY* server_pub_key= NULL;
            server_pub_key = PEM_read_PUBKEY(puntFile,NULL, NULL, NULL);

            if (server_pub_key == NULL){

                printf("Errore nel caricamento della chiave pubblica del client");
            }


            fclose(puntFile);

            // EVP_PKEY_free(server_priv_key);


/////////////// FINE LEGGO CHIAVE PUBBLICA SERVER DA SOCKET ////////////////


/////////////INIZIO DERIVAZIONE SECRET //////////////////////

    size_t secret_len;
    unsigned char* secret = derive_shared_secret(my_privkey, server_pub_key, &secret_len);
    if (!secret) {
        printf("Failed to derive shared secret.\n");
        return -1;
    }


    //free(secret);  //ricrodarsi di liberare il secret


     

  


/////////////FINE DERIVAZIONE SECRET //////////////////////







//////////////// DERIVAZIONE CHIAVE SEGRETA Kab/////////////////

//hashiamo il segreto--> viene fuori un hash a 256 bit, peroò il cifrario che utilizziamo è 
//AES a 128, quindi la chiave è più grnade della dimensione della chiave che accetta il cifrario
//AES
    //derivo la chiave di sessione Kab
    //unsigned char* K_ab = session_key(EVP_sha256(),EVP_aes_128_gcm(),secret,secret_len,key_len);
    
    //const EVP_MD* Hash_type = EVP_sha256();
    //const EVP_CIPHER* Cipher_type = EVP_aes_128_gcm();


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

////////////////FINE DERIVAZIONE CHIAVE SEGERTA Kab/////////////////


        //inizializzo il vettore iv
        int iv;
        iv = abs(arc4random_uniform(1000000));
        encrypted_credentials.iv = iv;

        char* iv_stringa = NULL;
        iv_stringa = convertNumberToString(iv);

        unsigned char tag[TAG_SIZE];







        printf("Fai la tua scelta: \n");
        printf("1) Login \n");
        printf("2) Registrazione \n");

        


        int choice_val = 0;
        scanf("%d", &choice_val);

        

        char buf[LEN_MAX];

        strcpy(choice.value, convertNumberToString(choice_val));


        //invio la scelta fatta
        if (write(clien_fd, &choice , sizeof(choice)) < 0)
        {
            perror("Send error");
            exit(-1);
        }



        if (strcmp(choice.value,"1") == 0){
            printf("Esegui il login:\n ");

            //strcpy(credenziali.email, "");

            // char username[10];
            printf("Username: \n ");
            scanf("%s", &credenziali.username, LEN_MAX);


            //cifro username
            int ciphertext_username_len;
            unsigned char ciphertext_username[128]; //il controllo sull'username è fatto nel regex in utility
            ciphertext_username_len = encrypt_data(credenziali.username, sizeof(credenziali.username),k_ab , iv_stringa, ciphertext_username , tag);

            memcpy(encrypted_credentials.enc_username, ciphertext_username, ciphertext_username_len);


            //cifro l'email
            //printf("Email: \n ");
            //scanf("%s", &credenziali.email,LEN_MAX);

            strcpy(credenziali.email, "easteregg");

            int ciphertext_email_len;
            unsigned char ciphertext_email[256]; 
            ciphertext_email_len = encrypt_data(credenziali.email, sizeof(credenziali.email),k_ab , iv_stringa, ciphertext_email , tag);
            
            memcpy(encrypted_credentials.enc_email, ciphertext_email, ciphertext_email_len);


            // char passw[10];
            printf("Password: \n ");
            scanf("%s", &credenziali.password,LEN_MAX);            

             //cifro la password
            int ciphertext_password_len;
            unsigned char ciphertext_password[256]; 
            ciphertext_password_len = encrypt_data(credenziali.password, sizeof(credenziali.password),k_ab , iv_stringa, ciphertext_password , tag);
            
            memcpy(encrypted_credentials.enc_password, ciphertext_password, ciphertext_password_len);


            //metto il campo vuoto nella email
            //unsigned char* email_string = "vuoto";

           // strcpy(encrypted_credentials.enc_email,email_string);






             //invio le credenziali cifrate
            if (write(clien_fd, &encrypted_credentials , sizeof(encrypted_credentials)) < 0)
            {
                perror("Send error");
                exit(-1);
            }



            //leggo la risposta del server alla mia richiesta di login
            if (read(clien_fd, &conferma ,sizeof(conferma)) < 0)
            {
                perror("Read error\n");
                exit(-1);
            }

            if(strcmp(conferma.risposta,"-2") == 0){


                printf("Wrong Password :( \n");
                

            }else if(strcmp(conferma.risposta,"-1") == 0){

                printf("User not found, you need to register");
                return 0;

            }else{ //ti sei loggato correttamente

                welcome_message(); 

                int choice_to_logout =0;

                printf(ANSI_COLOR_GREEN "Successful login!" ANSI_COLOR_RESET "\n");

                while(1){
                    
                    printf("Choose what to do: \n 1) Make a post \n 2) List latest messages  \n 3) Download a message \n ");
                    printf("\n\nPress 4 to logout.\n");


                    //int val = get_user_choice();
                    
                
                    int val = 0;
                    scanf("%d", &val);
                    
                    //char buf[LEN_MAX];
                    strcpy(choice.value, convertNumberToString(val));

                    //invio la scelta fatta
                    if (write(clien_fd, &choice , sizeof(choice)) < 0)
                    {
                        perror("Send error");
                        exit(-1);
                    }



                    if(val == 4){

                        //strcpy(choice.value,"0");
                        printf("We'll miss you :(\n");
                        return 0;
                    }

                    //printf("choice = %d", choice.value);

                    if(strcmp(choice.value,"1") == 0){


                        //getchar(); //toglie lo \n rimasto nel buffer
                        getchar();
                        
                        printf("Qual è il titolo del tuo post? \n");
                        fgets(post.title, LEN_MAX, stdin);

                        // Rimuovi il newline dal titolo, se presente
                        size_t len = strlen(post.title);
                        if (len > 0 && post.title[len-1] == '\n') {
                            post.title[len-1] = '\0';
                        }

                        printf("Scrivi il post: \n");
                        fgets(post.body, sizeof(post.body), stdin);

                        // Rimuovi il newline dal corpo del post, se presente
                        len = strlen(post.body);
                        if (len > 0 && post.body[len-1] == '\n') {
                            post.body[len-1] = '\0';
                        }
                        


                        //printf("title: %s\n", post.title);
                        //printf("body = %s\n", post.body);

                        //adesso cifro il titolo 
                        int ciphertext_title_len;
                        unsigned char ciphertext_title[LEN_MAX]; 
                        ciphertext_title_len = encrypt_data(post.title, sizeof(post.title),k_ab , iv_stringa, ciphertext_title , tag);
                        memcpy(enc_post.enc_title, ciphertext_title, ciphertext_title_len);


                        //adesso cifro il body 
                        int ciphertext_body_len;
                        unsigned char ciphertext_body[BODY_LEN]; 
                        ciphertext_body_len = encrypt_data(post.body, sizeof(post.body),k_ab , iv_stringa, ciphertext_body , tag);
                        memcpy(enc_post.enc_body, ciphertext_body, ciphertext_body_len);  


                        //metto l'username cifrato dentro l'autore in ENC_POST

                        //memcpy(enc_post.enc_author, encrypted_credentials.enc_username, ciphertext_username_len);


                        //invio il messaggio che l'utente vuole postare nel forum
                        if (write(clien_fd, &enc_post , sizeof(enc_post)) < 0)
                        {
                            perror("Send error");
                            exit(-1);
                        }




                    }else if(strcmp(choice.value, "2") == 0){ //list all n available messages


                        //leggo il numero di messaggi totale cifrato
                        if (read(clien_fd, &enc_choice ,sizeof(enc_choice)) < 0)
                        {
                            perror("Read error\n");
                            exit(-1);
                        }

                        //decifro il num di messaggi totali
                        int plaintext_num_mgs_len;
                        unsigned char plaintext_num_msgs[256]; 
                        plaintext_num_mgs_len = decrypt_data(enc_choice.enc_value, sizeof(enc_choice.enc_value), k_ab, iv_stringa, plaintext_num_msgs, tag  );

                        strcpy(choice.value, plaintext_num_msgs ); //mettiamo il numero di messaggi totale in choice.value, è una stringa

                        //printf("num mess = %s", choice.value);

                        int msg_to_print;
                        printf("Quanti messaggi vuoi listare? \n In totale ci sono : %s messaggi\n", plaintext_num_msgs );
                        scanf("%d", &msg_to_print);

                        while(msg_to_print > atoi(choice.value) ){

                            printf("Non ci sono così tanti messaggi!\n");
                            scanf("%d", &msg_to_print);
                        };

                        char* num_msgs_to_list = convertNumberToString(msg_to_print); //num dimex da stampare sotto forma di stringa




                        //cifro il numero di messaggi che l'utente vuole listare
                        int ciphertext_num_msgs_to_print_len;
                        unsigned char ciphertext_num_msgs_to_print[256]; 
                        ciphertext_num_msgs_to_print_len = encrypt_data(num_msgs_to_list, sizeof(num_msgs_to_list),k_ab , iv_stringa, ciphertext_num_msgs_to_print , tag);
            
                        memcpy(enc_choice.enc_value,ciphertext_num_msgs_to_print,ciphertext_num_msgs_to_print_len);


                        //Scrivo nella socket il numero totale di messaggi chel'utente vuole stampare 
                        if (write(clien_fd, &enc_choice, sizeof(enc_choice)) < 0) {
                            perror("Num msgs to print Send error");
                            return -1;
                        }



                        printf(ANSI_COLOR_MAGENTA "----------------------------------------------------------------------------------------------------------------------"ANSI_COLOR_RESET"\n");
                        printf(ANSI_COLOR_MAGENTA"| %-15s | %-15s | %-15s | %-60s |"ANSI_COLOR_RESET"\n", "ID", "User", "Title", "Message");
                        printf(ANSI_COLOR_MAGENTA"----------------------------------------------------------------------------------------------------------------------"ANSI_COLOR_RESET"\n");
                        for(int i = 0; i < msg_to_print; i++){

                            //leggo i messaggi da listare
                            if (read(clien_fd, &enc_msg_to_list ,sizeof(enc_msg_to_list)) < 0)
                            {
                                perror("Read error\n");
                                exit(-1);
                            }


                            //decifro l'id
                            int plaintext_id_len;
                            unsigned char plaintext_id[128]; 
                            plaintext_id_len = decrypt_data(enc_msg_to_list.enc_id, sizeof(enc_msg_to_list.enc_id), k_ab, iv_stringa, plaintext_id, tag  );

                            strcpy(msg_to_list.id,plaintext_id);

                            //printf("%s, ", msg_to_list.id);

                            //decifro l'username
                            int plaintext_username_len;
                            unsigned char plaintext_username[128]; 
                            plaintext_username_len = decrypt_data(enc_msg_to_list.enc_username, sizeof(enc_msg_to_list.enc_username), k_ab, iv_stringa, plaintext_username, tag  );

                            strcpy(msg_to_list.username,plaintext_username);

                            //printf("%s, ", msg_to_list.username);


                            //decifro il titolo
                            int plaintext_title_len;
                            unsigned char plaintext_title[BODY_LEN]; 
                            plaintext_title_len = decrypt_data(enc_msg_to_list.enc_title, sizeof(enc_msg_to_list.enc_title), k_ab, iv_stringa, plaintext_title, tag  );

                            strcpy(msg_to_list.title,plaintext_title);

                            //printf("%s, ", msg_to_list.title);


                            //decifro il messaggio
                            int plaintext_msg_len;
                            unsigned char plaintext_msg[BODY_LEN]; 
                            plaintext_msg_len = decrypt_data(enc_msg_to_list.enc_msg, sizeof(enc_msg_to_list.enc_msg), k_ab, iv_stringa, plaintext_msg, tag  );

                            strcpy(msg_to_list.msg,plaintext_msg);

                            //printf("%s", msg_to_list.msg);

                            printf("| %-15s | %-15s | %-15s | %-35s \n", msg_to_list.id,  msg_to_list.username, msg_to_list.title, msg_to_list.msg);

                        }

                        printf(ANSI_COLOR_MAGENTA"----------------------------------------------------------------------------------------------------------------------"ANSI_COLOR_RESET"\n");

                        strcpy(plaintext_num_msgs,"0");
                        

                    }else if (strcmp(choice.value,"3") == 0){ 


                        //leggo il numero di messaggi totale cifrato
                        if (read(clien_fd, &enc_choice ,sizeof(enc_choice)) < 0)
                        {
                            perror("Read error\n");
                            exit(-1);
                        }

                        //decifro il num di messaggi totali
                        int plaintext_num_mgs_len;
                        unsigned char plaintext_num_msgs[64]; 
                        plaintext_num_mgs_len = decrypt_data(enc_choice.enc_value, sizeof(enc_choice.enc_value), k_ab, iv_stringa, plaintext_num_msgs, tag  );

                        strcpy(choice.value, plaintext_num_msgs ); //mettiamo il numero di messaggi totale in choice.value, è una stringa





                        printf("--->Imessaggi totali sono: %s\n", choice.value);
                        printf("--->Inserisci l'id del messaggio che vuoi salvarti: ");

                        int msg_to_save;
                        scanf("%d", &msg_to_save);

                        //int tot_mex = atoi(choice.value);




                        unsigned char* msg_to_save_string;
                        msg_to_save_string = convertNumberToString(msg_to_save);


                        //cifro l'id del messaggio che l'utente vuole salvarsi
                        int ciphertext_msg_id_to_save_len;
                        unsigned char ciphertext_msg_id_to_save[10]; 
                        ciphertext_msg_id_to_save_len = encrypt_data(msg_to_save_string, sizeof(msg_to_save_string),k_ab , iv_stringa, ciphertext_msg_id_to_save , tag);
            
                        memcpy(enc_choice.enc_value,ciphertext_msg_id_to_save,ciphertext_msg_id_to_save_len);

                        //printf("enc choice: %s", enc_choice.enc_value);


                        //Scrivo nella socket l'id del messaggio che l'utente vuole salvarsi
                        if (write(clien_fd, &enc_choice, sizeof(enc_choice)) < 0) {
                            perror("Num msgs to print Send error");
                            return -1;
                        }


                        //leggo i messaggi da listare
                        if (read(clien_fd, &enc_msg_to_list ,sizeof(enc_msg_to_list)) < 0)
                        {
                            perror("Read error\n");
                            exit(-1);
                        }


                        //decifro l'username
                        int plaintext_username_len;
                        unsigned char plaintext_username[128]; 
                        plaintext_username_len = decrypt_data(enc_msg_to_list.enc_username, sizeof(enc_msg_to_list.enc_username), k_ab, iv_stringa, plaintext_username, tag  );

                        strcpy(msg_to_list.username,plaintext_username);

                        //printf("%s, ", msg_to_list.username);


                        //decifro il titolo
                        int plaintext_title_len;
                        unsigned char plaintext_title[BODY_LEN]; 
                        plaintext_title_len = decrypt_data(enc_msg_to_list.enc_title, sizeof(enc_msg_to_list.enc_title), k_ab, iv_stringa, plaintext_title, tag  );

                        strcpy(msg_to_list.title,plaintext_title);

                        //printf("%s, ", msg_to_list.title);


                        //decifro il messaggio
                        int plaintext_msg_len;
                        unsigned char plaintext_msg[BODY_LEN]; 
                        plaintext_msg_len = decrypt_data(enc_msg_to_list.enc_msg, sizeof(enc_msg_to_list.enc_msg), k_ab, iv_stringa, plaintext_msg, tag  );

                        strcpy(msg_to_list.msg,plaintext_msg);

                        //printf("%s", msg_to_list.msg);


                        int argc = 0;
                        char **argv = NULL;
                        gtk_init(&argc, &argv);



                        //routine per salvare file e scrittura in folder scelta da utente
                        open_dialog(&msg_to_list.username, &msg_to_list.title, &msg_to_list.msg);

                        printf("--->Hai correttamente salvato il tuo messaggio :)\n");

                    }else{

                        printf("Wrong choice\n");

                    }

                }


            }


            //leggo se è avvenuto un login con successo




            //printf("Credentials: \n Email: %s \n Username: %s \n Password: %s \n ", &credenziali.email, &credenziali.username, &credenziali.password);


        // FASE DI REGISTRAZIONE
        }else if(strcmp(choice.value,"2") == 0) {

            /*
            
            generazione chiave pubblica privata RSA + Diffie Hellman

            */

            printf("Hai scelto di avviare la registrazione:\n ");

            // char username[10];
            printf("Username: \n ");
            scanf("%s", &credenziali.username,LEN_MAX);


            //cifro username
            int ciphertext_username_len;
            unsigned char ciphertext_username[128]; //il controllo sull'username è fatto nel regex in utility
            ciphertext_username_len = encrypt_data(credenziali.username, sizeof(credenziali.username),k_ab , iv_stringa, ciphertext_username , tag);

            memcpy(encrypted_credentials.enc_username,ciphertext_username,ciphertext_username_len);
           
/*
            printf("Ciphertext: ");

            for (int i = 0; i < ciphertext_username_len; i++)
            {
                printf("%02x", ciphertext_username[i]);
            }
*/
           


            //char email[10];
            printf("\nEmail: \n");
            scanf("%s", &credenziali.email, LEN_MAX);
            
            //cifro email
            int ciphertext_email_len;
            unsigned char ciphertext_email[256]; 
            ciphertext_email_len = encrypt_data(credenziali.email, sizeof(credenziali.email),k_ab , iv_stringa, ciphertext_email, tag );
            
            memcpy(encrypted_credentials.enc_email,ciphertext_email,ciphertext_email_len);
           


            // char passw[10];
            printf("Password: \n ");
            scanf("%s", &credenziali.password,LEN_MAX);


            //cifro la password
            int ciphertext_password_len;
            unsigned char ciphertext_password[256]; 
            ciphertext_password_len = encrypt_data(credenziali.password, sizeof(credenziali.password),k_ab , iv_stringa, ciphertext_password , tag);
            
            memcpy(encrypted_credentials.enc_password,ciphertext_password,ciphertext_password_len);



             //invio le credenziali cifrate
            if (write(clien_fd, &encrypted_credentials , sizeof(encrypted_credentials)) < 0)
            {
                perror("Send error");
                exit(-1);
            }




            printf("Credentials: \n Email: %s \n Username: %s \n Password: %s \n ", &credenziali.email, &credenziali.username, &credenziali.password);

/*
            //invio le credenziali
            if (write(clien_fd, &credenziali , sizeof(credenziali)) < 0)
            {
                perror("Send error");
                exit(-1);
            }
*/

            
            printf("Inserisci il codice inviato a %s : \n", credenziali.email );
            scanf("%d", &input_challenge.value);

            if (write(clien_fd, &input_challenge , sizeof(input_challenge)) < 0)
            {
                perror("Send error");
                exit(-1);
            }

            

            //leggo dalla socket se la registrazione è andata a buon fine--cifrata
            if (read(clien_fd, &enc_choice ,sizeof(enc_choice)) < 0)
            {
                perror("Read error\n");
                exit(-1);
            }


            //decifro 
            int registration_confirmation_len;
            unsigned char registration_confirmation[20]; 
            registration_confirmation_len = decrypt_data(enc_choice.enc_value, sizeof(enc_choice.enc_value), k_ab, iv_stringa, registration_confirmation, tag  );



            strcpy(choice.value,registration_confirmation); 



            if (strcmp(choice.value,"1") == 0){

                printf("Ti sei registrato correttamente, prosegui facendo il login!\n");
                return 0;

            }else if(strcmp(choice.value,"-1") == 0){

                printf("C'è stato un problema nella registrazione, riprova.\n");
                return 0;


            }










/*

            //controlliamo se il processo di registrazione è andato a buon fine, altrimenti
            // cancelliamo le chiavi pubbich e private

            read(clien_fd, &error,sizeof(error));
            if( error.risposta == -1){


                RSA_key_deletion(credenziali.username);


            }

*/








    //    } //parentesi del while

    }





    close(clien_fd); //chiudere la socket dopo la risposta del server
    return 0;

}