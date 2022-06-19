/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <errno.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "App.h"
#include "Enclave_u.h"

#define VOTE_LEN SGX_RSA3072_KEY_SIZE*2


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;



/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}




/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}



/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void ocall_write_file(uint8_t* data, size_t size, const char* filename) {
    if (data == NULL || size <= 0L || filename == NULL) return;

    FILE* fd;
    fd = fopen(filename, "wb");
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }
    fwrite(data, size, 1, fd);
    fclose(fd);

}




/* Available action */
void generateCredentials() {
    ecall_gen_credentials(global_eid);
}

void exportPublicKey() {
    // read sealed credentials
    FILE* fd;
    char credentialsFilename[] = "./ballot.seal";
    fd = fopen(credentialsFilename, "rb");
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }

    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* sealed_data = (uint8_t*) malloc(fsize);

    fread(sealed_data, fsize, 1, fd);
    fclose(fd);


    // ecall to unseal credentials
    ecall_unseal_and_export_pub(global_eid, sealed_data, fsize);
}

void runElection() {
    // load ballot box sealed credentials (./ballot.seal)
    FILE* fd;
    char credentialsFilename[] = "./ballot.seal";
    fd = fopen(credentialsFilename, "rb");
    if (fd == NULL) {
        printf("Error loading the ballot box sealed credentials\n");
        return;
    }

    fseek(fd, 0, SEEK_END);
    long sealed_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);
    fread(sealed_data, sealed_size, 1, fd);
    fclose(fd);

    // laod list of public keys from authorized voters (../keys/*)
    DIR* dir;
    dir = opendir("../keys/");  
    if (dir==NULL) {
        printf("Error loading list of authorized voters\n");
    }

    struct dirent *ent;
    int authorizedVotersCount = 0;
    while ((ent = readdir(dir)) != NULL){
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            continue;
        }

        if (ent->d_type == DT_REG) {
            authorizedVotersCount++;
        }
    }

    size_t authorizedVotersPubicKeysLen = authorizedVotersCount * SGX_SHA256_HASH_SIZE * sizeof(uint8_t);
    uint8_t* authorizedVotersPubicKeys = (uint8_t*) malloc(authorizedVotersPubicKeysLen);
    
    rewinddir(dir);
    long data_size = -1L;
    char* filename;

    for (int i = 0; i < authorizedVotersCount; i++ ) {
        ent = readdir(dir);
        if (ent == NULL) {
            printf("Error loading list of authorized voters\n");
            break;
        }
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            i--;
            continue;
        }

        if (ent->d_type == DT_REG) {

            filename = (char*) malloc(sizeof(ent->d_name) + 9);
            memset(filename, 0, sizeof(ent->d_name) + 9);
            memcpy(filename, "../keys/", 8);

            fd = fopen(strcat(filename, ent->d_name), "rb");
            if (fd == NULL) {
                printf("Error loading the ballot box sealed credentials\n");
                return;
            }
            
            fseek(fd, 0, SEEK_END);
            data_size = ftell(fd);
            fseek(fd, 0, SEEK_SET);
            if (data_size != SGX_SHA256_HASH_SIZE) {
                fclose(fd);
                continue;
            }


            fread(authorizedVotersPubicKeys + i*SGX_SHA256_HASH_SIZE, SGX_SHA256_HASH_SIZE, 1, fd);
            fclose(fd);
        }

    }
    closedir(dir);

    // load all the votes (../votes/)
    dir = opendir("../votes/");  
    if (dir==NULL) {
        printf("Error loading list of casted votes\n");
    }

    int votesCount = 0;
    while ((ent = readdir(dir)) != NULL){
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            continue;
        }

        if (ent->d_type == DT_REG) {
            votesCount++;
        }
    }

    size_t votesLen = votesCount * SGX_RSA3072_KEY_SIZE*2* sizeof(uint8_t);
    uint8_t* votes = (uint8_t*) malloc(votesLen);
   
    rewinddir(dir);
    data_size = -1L;

    for (int i = 0; i < votesCount; i++ ) {
        ent = readdir(dir);
        if (ent == NULL) {
            printf("Error loading list of casted votes\n");
            break;
        }
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            i--;
            continue;
        }

        if (ent->d_type == DT_REG) {

            filename = (char*) malloc(sizeof(ent->d_name) + 10);
            memset(filename, 0, sizeof(ent->d_name) + 10);
            memcpy(filename, "../votes/", 9);

            fd = fopen(strcat(filename, ent->d_name), "rb");
            if (fd == NULL) {
                printf("Error loading list of casted votes\n");
                return;
            }

            fseek(fd, 0, SEEK_END);
            data_size = ftell(fd);
            fseek(fd, 0, SEEK_SET);
            if (data_size != VOTE_LEN) {
                fclose(fd);
                continue;
            }
            

            fread(votes + i*VOTE_LEN, VOTE_LEN, 1, fd);
            fclose(fd);
        }

    }
    closedir(dir);

   // ecall to run election inside the enclave
   ecall_run_election(global_eid, sealed_data, sealed_size, authorizedVotersPubicKeys, authorizedVotersPubicKeysLen, votes, votesLen);

}

void checkVoteStatus(char* voterPublicKeyFilename) {
    // load ballot box sealed credentials (./ballot.seal)
    FILE* fd;
    char credentialsFilename[] = "./ballot.seal";
    fd = fopen(credentialsFilename, "rb");
    if (fd == NULL) {
        printf("Error loading the ballot box sealed credentials\n");
        return;
    }

    fseek(fd, 0, SEEK_END);
    long sealed_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);
    fread(sealed_data, sealed_size, 1, fd);
    fclose(fd);

    // laod list of public keys from authorized voters (../keys/*)
    DIR* dir;
    dir = opendir("../keys/");  
    if (dir==NULL) {
        printf("Error loading list of authorized voters\n");
    }

    struct dirent *ent;
    int authorizedVotersCount = 0;
    while ((ent = readdir(dir)) != NULL){
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            continue;
        }

        if (ent->d_type == DT_REG) {
            authorizedVotersCount++;
        }
    }

    size_t authorizedVotersPubicKeysLen = authorizedVotersCount * SGX_SHA256_HASH_SIZE * sizeof(uint8_t);
    uint8_t* authorizedVotersPubicKeys = (uint8_t*) malloc(authorizedVotersPubicKeysLen);
    uint8_t* voterToCkeckPublicKey = (uint8_t*) malloc(SGX_SHA256_HASH_SIZE * sizeof(uint8_t));
    
    rewinddir(dir);
    long data_size = -1L;
    char* filename;

    for (int i = 0; i < authorizedVotersCount; i++ ) {
        ent = readdir(dir);
        if (ent == NULL) {
            printf("Error loading list of authorized voters\n");
            break;
        }
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            i--;
            continue;
        }

        if (ent->d_type == DT_REG) {

            filename = (char*) malloc(sizeof(ent->d_name) + 9);
            memset(filename, 0, sizeof(ent->d_name) + 9);
            memcpy(filename, "../keys/", 8);

            fd = fopen(strcat(filename, ent->d_name), "rb");
            if (fd == NULL) {
                printf("Error loading the ballot box sealed credentials\n");
                return;
            }
            
            fseek(fd, 0, SEEK_END);
            data_size = ftell(fd);
            fseek(fd, 0, SEEK_SET);
            if (data_size != SGX_SHA256_HASH_SIZE) {
                fclose(fd);
                continue;
            }

            fread(authorizedVotersPubicKeys + i*SGX_SHA256_HASH_SIZE, SGX_SHA256_HASH_SIZE, 1, fd);
            fclose(fd);
            if (strcmp(filename, voterPublicKeyFilename) == 0) {
                memcpy(voterToCkeckPublicKey, authorizedVotersPubicKeys + i*SGX_SHA256_HASH_SIZE, SGX_SHA256_HASH_SIZE);
            }
        }

    }
    closedir(dir);


    // load all the votes (../votes/)
    dir = opendir("../votes/");  
    if (dir==NULL) {
        printf("Error loading list of casted votes\n");
    }

    int votesCount = 0;
    while ((ent = readdir(dir)) != NULL){
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            continue;
        }

        if (ent->d_type == DT_REG) {
            votesCount++;
        }
    }

    size_t votesLen = votesCount * SGX_RSA3072_KEY_SIZE*2* sizeof(uint8_t);
    uint8_t* votes = (uint8_t*) malloc(votesLen);
   
    rewinddir(dir);
    data_size = -1L;

    for (int i = 0; i < votesCount; i++ ) {
        ent = readdir(dir);
        if (ent == NULL) {
            printf("Error loading list of casted votes\n");
            break;
        }
        if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)){
            i--;
            continue;
        }

        if (ent->d_type == DT_REG) {

            filename = (char*) malloc(sizeof(ent->d_name) + 10);
            memset(filename, 0, sizeof(ent->d_name) + 10);
            memcpy(filename, "../votes/", 9);

            fd = fopen(strcat(filename, ent->d_name), "rb");
            if (fd == NULL) {
                printf("Error loading list of casted votes\n");
                return;
            }

            fseek(fd, 0, SEEK_END);
            data_size = ftell(fd);
            fseek(fd, 0, SEEK_SET);
            if (data_size != VOTE_LEN) {
                fclose(fd);
                continue;
            }

            fread(votes + i*VOTE_LEN, VOTE_LEN, 1, fd);
            fclose(fd);
        }

    }
    closedir(dir);
    ecall_check_voter(global_eid, sealed_data, sealed_size, authorizedVotersPubicKeys, authorizedVotersPubicKeysLen, votes, votesLen, voterToCkeckPublicKey, SGX_SHA256_HASH_SIZE);

}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int option;
    char* action = NULL;
    char* voterPublicKey = NULL;
    
    /* Handle command line options */
    while ((option = getopt(argc, argv, ":a:p:h")) != -1) {
        switch (option) {
            case 'a':
                if (strcasecmp(optarg, "GEN") != 0 && strcasecmp(optarg, "PUB") != 0 && strcasecmp(optarg, "RUN") != 0 && strcasecmp(optarg, "CHECK") != 0) {
                    printf("Action %s unknown.\n", optarg);
                    return 1;
                }
                action = optarg;
                break;

            case 'p':
                voterPublicKey = optarg;
                break;

            case 'h':
                printf("USAGE");
                return -1;

            case '?':
            default:
                if (optopt == 'a' || optopt == 'p') {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                } else {
                    printf("Unknown option, place check the help manual with -h\n");
                }
                return 1;
        }
    }



    /* Handle mandatory argument check */
    if (action == NULL) {
        printf("No action specified. Exiting..\n"); return 1;
    }
    if (voterPublicKey == NULL && (strcasecmp(action, "CHECK") == 0)) {
        printf("Action %s needs argument -p. Check help (-h) for more info.\n", action); return 1;
    }
   

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    /* Actions */
    if (strcasecmp(action, "GEN") == 0){
        // GEN
        generateCredentials();  

    } else if (strcasecmp(action, "PUB") == 0) {
        // PUB 
        exportPublicKey();  

    } else if (strcasecmp(action, "RUN") == 0) {
        // RUN
        runElection();

    } else {
        // VOTE
        checkVoteStatus(voterPublicKey);
    
    }
 

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("Info: Ballot Enclave successfully returned.\n");
    return 0;
}

