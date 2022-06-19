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
#include <assert.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <errno.h>
#include <uuid/uuid.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "App.h"
#include "Enclave_u.h"



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

void ocall_derive_key(uint8_t* key, size_t key_len, const char salt, char* password) {
    PKCS5_PBKDF2_HMAC_SHA1(password, -1, (const unsigned char*) &salt, 1, 1000, (int) key_len, key);
}

void ocall_write_file(uint8_t* data, size_t size, const char* directory, const char* extension) {
    if (data == NULL || size <= 0L || directory == NULL || extension == NULL) return;

    DIR* dir = opendir(directory);
    if (dir == NULL) {

        if (ENOENT == errno) {
            int ret = mkdir(directory, S_IRWXU);
            if (ret) {
                printf("ERROR creating a directory - data not stored");
                return;
            }
        } else {
            printf("ERROR opening directory - data not stored");
            return;
        }
    }
    closedir(dir);

    uuid_t binuuid;
    char *uuid = (char*) malloc(UUID_STR_LEN);
    size_t filename_size = UUID_STR_LEN + strlen(directory) + strlen(extension) + 1;
    char* filename = (char*) malloc(filename_size);
    
    uuid_generate_random(binuuid);
    uuid_unparse_lower(binuuid, uuid);
    sprintf(filename, "%s/%s%s", directory, uuid, extension);

    FILE* fd;
    fd = fopen(filename, "wb");
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }

    fwrite(data, size, 1, fd);
    fclose(fd);
    printf("Data stored in %s\n", filename);

}




/* Available action */
void generateCredentials(char* passwd) {
    ecall_gen_credentials(global_eid, passwd);
}

void exportPublicKey(char* passwd, char* credentialFilename) {
    // read sealed credentials
    FILE* fd;
    fd = fopen(credentialFilename, "rb");

    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* sealed_data = (uint8_t*) malloc(fsize);
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }
    fread(sealed_data, fsize, 1, fd);
    fclose(fd);


    // ecall to unseal credentials
    sgx_status_t sgx_status = ecall_unseal_and_export_pub(global_eid, sealed_data, fsize, passwd);
    printf("%d\n", sgx_status);
}

void produceVote(char* vote, char* password, char* credentialsFile, char* ballotPubKey) {
    // read sealed credentials
    FILE* fd;
    fd = fopen(credentialsFile, "rb");

    fseek(fd, 0, SEEK_END);
    long sealed_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }
    fread(sealed_data, sealed_size, 1, fd);
    fclose(fd);

    // read ballot public key file
    fd = fopen(ballotPubKey, "rb");

    fseek(fd, 0, SEEK_END);
    long pubKeyLen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* pubKey = (uint8_t*) malloc(pubKeyLen);
    if (fd == NULL) {
        printf("Error opening a file\n");
        return;
    }
    fread(pubKey, pubKeyLen, 1, fd);
    fclose(fd);

    // ocall to vote
    ecall_produce_vote(global_eid, vote, sealed_data, sealed_size, password, pubKey, pubKeyLen);

}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    int option;
    char* action = NULL;
    char* credentialFilename = NULL;
    char* passwd = NULL;
    char* vote = NULL;


    /* Handle command line options */
    while ((option = getopt(argc, argv, ":a:c:p:v:h")) != -1) {
        switch (option) {
            case 'a':
                if (strcasecmp(optarg, "GEN") != 0 && strcasecmp(optarg, "PUB") != 0 && strcasecmp(optarg, "VOTE") != 0) {
                    printf("Action %s unknown.\n", optarg);
                    return 1;
                }
                action = optarg;
                break;

            case 'c':
                credentialFilename = optarg;
                break;

            case 'p':
                passwd = optarg;
                break;

            case 'v':
                if (strlen(optarg) >= 384) {
                    printf("Vote is too long to be casted.\n");
                    return -1;
                }
                vote = optarg;
                break;

            case 'h':
                printf("USAGE");
                return -1;

            case '?':
            default:
                if (optopt == 'a' || optopt == 'c' || optopt == 'p'|| optopt == 'v') {
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
    if (passwd == NULL) {
        printf("Action %s needs argument -p. Check help (-h) for more info.\n", action); return 1;
    }
    if (credentialFilename == NULL && (strcasecmp(action, "PUB") == 0 || strcasecmp(action, "VOTE") == 0)) {
        printf("Action %s needs argument -c. Check help (-h) for more info.\n", action); return 1;
    }
    if (vote == NULL && strcasecmp(action, "VOTE") == 0) {
        printf("Action %s needs argument -v. Check help (-h) for more info.\n", action); return 1;
    }


    // char passwd[] = "credentialsSecretPassword";
    // char credentialsFilename[] = "../creds/credentials.seal";
    // char vote[] = "veryLegitimateVote";


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 


    /* Actions */
    if (strcasecmp(action, "GEN") == 0){
        // GEN
        generateCredentials(passwd);    

    } else if (strcasecmp(action, "PUB") == 0) {
        // PUB 
        exportPublicKey(passwd, credentialFilename);   

    } else {
        // VOTE
        char ballotPubKey[] = "../Ballot/ballot"; 
        produceVote(vote, passwd, credentialFilename, ballotPubKey);
    
    }



    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("Info: Voter Enclave successfully returned.\n");  
    return 0;
}

