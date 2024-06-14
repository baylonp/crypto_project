#include <unistd.h>
#include <stdlib.h>
#include <stdio.h> 
#include <string.h>
#include <openssl/sha.h>


#include <regex.h>


//per arc4random
#include <bsd/stdlib.h>
#include <string.h>


//per eseguire script shell
#include <unistd.h>



#include <openssl/evp.h>

//serve per gtk, open dialog-box 
#include <gtk/gtk.h>

#include <ctype.h>

#define MAX_LINE_LENGTH 200
#define MAX_USERS 40
#define MAX_LEN 50


#define TAG_SIZE 16 // Dimensione del tag di autenticazione per AES-GCM (16 byte)


typedef struct {
    int id;
    char email[MAX_LINE_LENGTH];
    char username[MAX_LINE_LENGTH];
    char hashed_password[MAX_LINE_LENGTH];
    char salt[MAX_LINE_LENGTH];
} User;




int credentials_checker (char* email, char* username, char* password){


       /*
       (?=.{1,24}$): Questa parte del regex è un'asserzione anticipata
        positiva che garantisce che l'intero indirizzo email abbia una 
        lunghezza massima di 24 caratteri, compreso il carattere '@'. 
        {1,24} limita la lunghezza totale dell'indirizzo email

       */
        const char* pattern_email = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

        const char* pattern_username = "^[a-zA-Z0-9._%]{2,16}$"; //massimo 16 caratteri per l'username

        const char* pattern_pw = "^[a-zA-Z0-9._%+-]{5,22}$"; //minimo  caratteri 5, massimo 22

        // Compila il pattern
        regex_t regex;  
        

        //controllo email

        if (regcomp(&regex, pattern_email, REG_EXTENDED) != 0) {
                printf("email pattern compilation error \n");
        return -1;
        } else if (regexec(&regex, email, 0, NULL, 0) != 0) { // Esegui il match dell'email con il pattern
                printf("email must be in format <smth>@domain \n");
        return -1;
        }


        //controllo username

        if (regcomp(&regex, pattern_username, REG_EXTENDED) != 0) {
        printf("username pattern compilation error \n");
        return -1;
        } else if (regexec(&regex, username, 0, NULL, 0) != 0) { // Esegui il match dell'username con il pattern
                printf("username must be made of numbers and/or letters and/or ._% \n");
        return -1;
        }


        //controllo password

        if (regcomp(&regex, pattern_pw, REG_EXTENDED) != 0) {

        printf("password pattern compilation error \n");
        return -1;

        } else if (regexec(&regex, password, 0, NULL, 0) != 0) { // Esegui il match della pw con il pattern
                printf("pw must be at least 5 char, possible special characters are: ._%+- \n"); // c&iao <-- questa password così non ci va bene
        return -1;
        }


        return 1;

        regfree(&regex);




}



//#include "hash.h"
char* hash_string(const char* input, size_t len) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    char* hashed_string = (char*) malloc(2 * SHA256_DIGEST_LENGTH + 1);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, len);
    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {


        //sprintf(&hashed_string[i * 2], "%02x", hash[i]); prende il valore dell'i-esimo elemento dell'array hash, lo formatta in esadecimale con 2 cifre utilizzando il formato "%02x" e lo salva nella stringa hashed_string a partire dalla posizione i * 2. Questo codice viene utilizzato per c
        //onvertire i valori esadecimale dell'array hash in una stringa esadecimale più leggibile.
        
        sprintf(&hashed_string[i * 2], "%02x", hash[i]);
    }

    return hashed_string;
}




int registration (long int* id,char* email, char* username, char* password, int input_challenge, int real_random_challenge ){

        //controllo parametri passanti dal client

        if (credentials_checker(email, username, password) < 0){

                return -1;

        }

        char* hashed_string = NULL;

        // file pointer variable to store the value returned by
        // fopen
        FILE* dbptr;

        // opening the file in write mode
        dbptr = fopen("db.csv", "a+");

        // checking if the file is opened successfully
        if (dbptr == NULL) {
            perror("The file is not opened. The program will "
                "now exit.");
            return -1;
        }

        ////////////CALCOLO ID ///////////////////

        long current_pos = ftell(dbptr); // Salva la posizione corrente nel file
        rewind(dbptr);

        // Conta il numero di righe nel file
            
            char c;
            while ((c = fgetc(dbptr)) != EOF) {
                if (c == '\n') {
                    (*id )++;
                }
            }

        ////////////////////////////////////


        fseek(dbptr, current_pos, SEEK_SET); // Ritorna alla posizione corrente nel file
        
        //mi genero randomicamente il seed, lungo 4 byte
        char salt[4];
        arc4random_buf(salt, sizeof salt);

        char salt_hexString[13]; // 6 bytes * 2 (for hexadecimal representation) + 1 (for null terminator)

        for (int i = 0; i < sizeof(salt); i++) {
            sprintf(&salt_hexString[i*2], "%02x", salt[i]);
        }
        salt_hexString[12] = '\0'; // Make sure the string is null-terminated




        char password_concat[MAX_LEN];

        strcpy(password_concat,password); //mi copio la password in un array finito così strcpy non si lamenta
        strcat(password_concat, salt_hexString); //concateno il seed  alla password 


        //printf("Password + seed clear: %s\n", password_concat);


        char* rec_hashed_password=NULL;
        rec_hashed_password = hash_string(password_concat, strlen(password_concat));

        //printf("Hash SHA-2 con seed: %s\n", rec_hashed_password);










        //se la challenge è corretta, inserisco le credenziali nel DB
        if(input_challenge == real_random_challenge){

            //scrivo nel db le credenziali
            fprintf(dbptr, "%d,%s,%s,%s,%s",*id, email,username, rec_hashed_password, salt_hexString );
            fputs("\n", dbptr);
            fclose(dbptr);

            //libero l'hash che era nello heap
            free(rec_hashed_password);

            rec_hashed_password = NULL;

            return 1;   

        }else{
            fclose(dbptr);

            //libero l'hash che era nello heap
            free(rec_hashed_password);

            rec_hashed_password = NULL;

            return -1;
        }

            

}



int login(char* email, char* username, char* password ){



///////CARICAMENTO GLI UTENTI IN UNA STRUTTURA DATI ///////////
    // Apri il file CSV in modalità di lettura
    FILE *file = fopen("db.csv", "r");
    if (file == NULL) {
        perror("Errore durante l'apertura del file");
        exit(EXIT_FAILURE);
    }

    // Carica i dati dal file CSV in una struttura dati
    User users[MAX_USERS];
    int num_users = 0;
    char line[MAX_LINE_LENGTH];


    while (fgets(line, sizeof(line), file) != NULL && num_users < MAX_USERS) {
        // Analizza la riga per estrarre i dati dell'utente
        char *token = strtok(line, ",");  //strok() ha già un puntatore al token successivo, ecco perchè nelle chiamate successive si mette NULL

        users[num_users].id = atoi(token);

        token = strtok(NULL, ",");
        strcpy(users[num_users].email, token);

        token = strtok(NULL, ",");
        strcpy(users[num_users].username, token);

        token = strtok(NULL, ",");
        strcpy(users[num_users].hashed_password, token);

        token = strtok(NULL, ",");
        strcpy(users[num_users].salt, token);

        num_users++;
    }

        fclose(file);

///////FINE CARICAMENTO GLI UTENTI IN UNA STRUTTURA DATI ///////////


        //printf("l'hash nel db è: %s\n", users[5].hashed_password);
       //printf("l'hash della password che mi arriva è: %s\n", rec_hashed_password);


       for (int i = 0; i < num_users; i++) {
                                                            //si usa memcmp per comparare un hash ad una stringa, 64 byte è la lunghezza fissa di un hash
            if ((strcmp(users[i].username, username) == 0) ) {


                    
                

                char password_concat[MAX_LEN] = "";

                strcpy(password_concat, password);
                strcat(password_concat, users[i].salt ); //adesso in password_concat c'è la pw+salt

                //strcat() aggiunge un LF CR alla fine, lo tolgo perchè sballa il calcolo dell'hash
                password_concat[strlen(password_concat) -1]= '\0';

               // printf("pw+seed clear: %s\n", password_concat);

                char* rec_hashed_password=NULL;
                rec_hashed_password= hash_string(password_concat, strlen(password_concat));




                //se l'utente esiste e ha azzeccato la password ritorno l'id dell'utente
                if(memcmp(users[i].hashed_password, rec_hashed_password, 64) == 0){ //si usa memcmp per comparare un hash ad una stringa, 64 byte è la lunghezza fissa di un hash


                         return i;
                }else{ //se l'utente esiste ma ha sbagliato password 
                         return -2 ;
                }

 
            //printf("hash nel db: %s\n",users[i].hashed_password );
           // printf("hash arrivato: %s\n",rec_hashed_password );

                //printf("%d", i);
            }

            //printf("%s,%s,%s \n", users[i].username,users[i].email, users[i].hashed_password);
        }

       

        return -1; // Credenziali non valide




}

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void welcome_message() {



 printf(ANSI_COLOR_MAGENTA "  /$$$$$$                                /$$$$$$$$                                            " ANSI_COLOR_RESET "\n");
 printf(ANSI_COLOR_MAGENTA " /$$__  $$                              | $$_____/                                           " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "| $$    $$ /$$$$$$$   /$$$$$$  /$$$$$$$ | $$     /$$$$$$   /$$$$$$  /$$   /$$ /$$$$$$/$$$$  " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "| $$$$$$$$| $$__  $$ /$$__  $$| $$__  $$| $$$$$ /$$__  $$ /$$__  $$| $$  | $$| $$_  $$_  $$ " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "| $$__  $$| $$    $$| $$    $$| $$    $$| $$__/| $$    $$| $$   __/| $$  | $$| $$   $$   $$ " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$   | $$  | $$| $$      | $$  | $$| $$ | $$ | $$ " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "| $$  | $$| $$  | $$|  $$$$$$/| $$  | $$| $$   |  $$$$$$/| $$      |  $$$$$$/| $$ | $$ | $$ " ANSI_COLOR_RESET"\n");
 printf(ANSI_COLOR_MAGENTA "|__/  |__/|__/  |__/  ______/ |__/  |__/|__/     ______/ |__/        ______/ |__/ |__/ |__/ " ANSI_COLOR_RESET"\n");
    printf("\n");
printf(ANSI_COLOR_MAGENTA"---------------------- Made by Luca Cremonese & Davide Di Rocco------------------------------------"ANSI_COLOR_RESET"\n");
printf("\n");
}




int challenge_fun(char* username, char* email_addr){

         int random_challenge;
        

  

        random_challenge = abs(arc4random_uniform(1000000)); //prendo solo valori positivi





        char buf[100];
        sprintf(buf, "./emal_send.sh %d %s %s", random_challenge , username, email_addr);
        system(buf);


        return random_challenge;

}




char* convertNumberToString(int num) {
    char numStr[20];
    sprintf(numStr, "%d", num);
    
    char* str = (char*) malloc(strlen(numStr) + 1);
    strcpy(str, numStr);
    
    return str;
}



int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char* tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



int decrypt_data(const unsigned char *ciphertext, int ciphertext_len ,  const unsigned char *key, const unsigned char *iv, unsigned char *plaintext,  const unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Creazione e inizializzazione del contesto del cifrario
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);

    // Decifratura dei dati
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    // Impostazione del tag di autenticazione
   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *) tag);

    // Verifica del tag di autenticazione
     EVP_DecryptFinal_ex(ctx, plaintext + len, &len);


    plaintext_len += len;

    // Liberazione della memoria allocata per il contesto del cifrario
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}





int add_to_db_of_messages(long int* msg_id,char* username, char* title, char* body ){



        // file pointer variable to store the value returned by
        // fopen
        FILE* dbptr;

        // opening the file in append mode
        dbptr = fopen("messages_db.csv", "a+");

        // checking if the file is opened successfully
        if (dbptr == NULL) {
            perror("The file is not opened. The program will "
                "now exit.");
            return -1;
        }

        ////////////CALCOLO ID ///////////////////

        long current_pos = ftell(dbptr); // Salva la posizione corrente nel file
        rewind(dbptr);


        // Conta il numero di righe nel file
            char c;
            while ((c = fgetc(dbptr)) != EOF) {
                if (c == '\n') {
                    (*msg_id )++;
                }
            }


        ////////////////////////////////////

            fseek(dbptr, current_pos, SEEK_SET); // Ritorna alla posizione corrente nel file
            
        //scrivo nel db i messaggi
            fprintf(dbptr, "%d,%s,%s,%s\n",*msg_id, username , title, body);
            //fputs("\n", dbptr);
            fclose(dbptr);


        return 0;

}


int get_number_of_messages(){


            int count = 0;
            FILE* dbptr;

        // opening the file in write mode
        dbptr = fopen("messages_db.csv", "a+");

        // checking if the file is opened successfully
        if (dbptr == NULL) {
            perror("The file is not opened. The program will "
                "now exit.");
            return -1;
        }

        ////////////CALCOLO ID ///////////////////

        long current_pos = ftell(dbptr); // Salva la posizione corrente nel file
        rewind(dbptr);

        // Conta il numero di righe nel file
            
            char c;
            while ((c = fgetc(dbptr)) != EOF) {
                if (c == '\n') {
                    count++;
                }
            }

        ////////////////////////////////////
        
        fseek(dbptr, current_pos, SEEK_SET); // Ritorna alla posizione corrente nel file


        fclose(dbptr);
        return (count);
}




// Function to write the data to the chosen file
void save_to_file(const char *filename, const char *username, const char *title, const char *message_body) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing\n");
        return;
    }
    
    fprintf(file, "Username: %s\n", username);
    fprintf(file, "Title: %s\n", title);
    fprintf(file, "Message Body:\n%s\n", message_body);
    
    fclose(file);


    //printf("Il messaggio è stato salvato correttamente a: %s", filename);

    
}

// Callback function for the "response" signal of the file chooser dialog
void on_file_save_response(GtkDialog *dialog, gint response_id, gpointer user_data) {
    if (response_id == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        char *filename = gtk_file_chooser_get_filename(chooser);
        
        // Retrieve the data passed via user_data
        const char **data = (const char **)user_data;
        const char *username = data[0];
        const char *title = data[1];
        const char *message_body = data[2];
        
        // Save the data to the chosen file
        save_to_file(filename, username, title, message_body);
        
        g_free(filename);
    }
    
    gtk_widget_destroy(GTK_WIDGET(dialog));

    gtk_main_quit(); // Quit the GTK main loop
    

    
}

 open_dialog( char *username,  char *title,  char *message_body  ) {
    // Initialize GTK

    // Get the data from command line arguments
    //const char *username = argv[1];
    //const char *title = argv[2];
    //const char *message_body = argv[3];
    
    // Create a new file chooser dialog for saving a file
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Save File",
                                                    NULL,
                                                    GTK_FILE_CHOOSER_ACTION_SAVE,
                                                    "_Cancel", GTK_RESPONSE_CANCEL,
                                                    "_Save", GTK_RESPONSE_ACCEPT,
                                                    NULL);
    
    // Set a default filename
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "untitled.txt");
    
    // Set the callback for the dialog's "response" signal
    const char *data[] = {username, title, message_body};
    g_signal_connect(dialog, "response", G_CALLBACK(on_file_save_response), (gpointer)data);
    
    // Show the dialog and start the GTK main loop
    gtk_widget_show_all(dialog);
    gtk_main();

    

}







