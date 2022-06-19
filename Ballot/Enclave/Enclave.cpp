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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <sgx_trts.h>
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#define VOTE_LEN SGX_RSA3072_KEY_SIZE*2
#define N_LEN SGX_RSA3072_KEY_SIZE
#define E_LEN 4


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int comparePublicKeys(uint8_t* publicKeyInVote, size_t publicKeyInVoteLen, uint8_t* publicKey, size_t publicKeyLen) {
    if (publicKeyInVote == NULL || publicKeyInVoteLen <= 0L || publicKey == NULL || publicKeyLen <= 0L) return 0;
    if (publicKeyInVoteLen != publicKeyLen) return 0;

    for (size_t j=0; j<publicKeyLen; j++) {
        if (*(publicKey + j) != *(publicKeyInVote + j)) {
            break;
        }
        return 1;
    }
    return 0;
}

int isAuthorizedVoter(uint8_t* publicKeyInVote, size_t keyLen, uint8_t* listOfAuthorizedVoters, size_t listLen) {
    if (publicKeyInVote == NULL || keyLen <= 0 || listOfAuthorizedVoters == NULL || listLen <= 0) return 0;

    int numAuthVoters = (int) listLen / SGX_SHA256_HASH_SIZE; 
    for (int i = 0; i<numAuthVoters; i++) {

        if (comparePublicKeys(publicKeyInVote, SGX_SHA256_HASH_SIZE, listOfAuthorizedVoters + i*SGX_SHA256_HASH_SIZE, SGX_SHA256_HASH_SIZE)) {
            return 1;
        }

    }
    return 0;
}


void ecall_gen_credentials() {
    uint8_t* n = (uint8_t*) malloc(N_LEN);
    uint8_t* d = (uint8_t*) malloc(N_LEN);
    long e = 65537;

    uint8_t* p = (uint8_t*) malloc(N_LEN);
    uint8_t* q = (uint8_t*) malloc(N_LEN);

    uint8_t* dmp1 = (uint8_t*) malloc(N_LEN);
    uint8_t* dmq1 = (uint8_t*) malloc(N_LEN);
    uint8_t* iqmp = (uint8_t*) malloc(N_LEN);

    // generate RSA key pair to act as credentials
    sgx_status_t sgx_status = sgx_create_rsa_key_pair(N_LEN, E_LEN, n, d, (unsigned char*)&e, p, q, dmp1, dmq1, iqmp);
    if (sgx_status != SGX_SUCCESS) {
        printf("ERROR on the creation of the key pairs %d\n", sgx_status);
        return;
    }

    free(p);
    free(q);
    free(dmp1);
    free(dmq1);
    free(iqmp);

    size_t credLen = E_LEN + 2 * N_LEN * sizeof(uint8_t) + 1; 
    uint8_t* cred = (uint8_t*) malloc(credLen);
    memcpy(cred, n, N_LEN);
    memcpy(cred+N_LEN, (unsigned char*)&e, E_LEN);
    cred[N_LEN + E_LEN] = (uint8_t) '\n';
    memcpy(cred+N_LEN+E_LEN+1, d, N_LEN);
    free(d);
    free(n);

    // seal the ballot credentials (using MRSIGNER)
    size_t sealed_size = sgx_calc_sealed_data_size(0, (uint32_t) credLen);
    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);

    sgx_status = sgx_seal_data(0, NULL, (uint32_t) credLen, cred, (uint32_t) sealed_size, (sgx_sealed_data_t*) sealed_data);
    free(cred);
    if (sgx_status != SGX_SUCCESS) {
        printf("ERROR while sealing the credentials %d\n", sgx_status);
        return; 
    }
    

    ocall_write_file(sealed_data, sealed_size, "ballot.seal");
    free(sealed_data);
    
}

void ecall_unseal_and_export_pub(uint8_t* sealed, size_t sealedLen) {
    if (sealed == NULL || sealedLen <= 0L) return;

    size_t macLen = sgx_get_add_mac_txt_len((sgx_sealed_data_t*) sealed);
    size_t credLen = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) sealed);

    uint8_t* cred = (uint8_t*) malloc(credLen);
    sgx_status_t sgx_status = sgx_unseal_data((sgx_sealed_data_t*) sealed, NULL, (uint32_t*)&macLen, cred, (uint32_t*)&credLen);
    if (sgx_status != SGX_SUCCESS) {
        printf("Failed to unseal data\n");
        return;
    }


    // extract public key from credentials
    size_t pubKeyLen = E_LEN + N_LEN * sizeof(uint8_t);
    uint8_t* pubKey = (uint8_t*) malloc(pubKeyLen);
    memcpy(pubKey, cred, pubKeyLen);
    

    // expot to the outside
    ocall_write_file(pubKey, pubKeyLen, "ballot");  
}

void ecall_run_election(uint8_t* sealed_data, size_t sealed_size, uint8_t* authorizedVoters, size_t authorizedVotersLen, uint8_t* votes, size_t votesLen) {
    if (sealed_data == NULL || sealed_size <= 0L || authorizedVoters == NULL || authorizedVotersLen <= 0L || votes == NULL || votesLen <= 0L) {
        return;
    }


    int votesCount = (int) votesLen / (SGX_RSA3072_KEY_SIZE*2);
    int authVotersCount = (int) authorizedVotersLen / SGX_SHA256_HASH_SIZE; 
    int validVoteCount = 0;
    size_t shuffledMaxLen = votesLen/2 - (SGX_SHA256_HASH_SIZE*votesCount);
    uint8_t* shuffledVotes = (uint8_t*) malloc(shuffledMaxLen);     // max len it can possibly have (vote string <= 384)
    size_t size = shuffledMaxLen / votesCount;                      // (max) size of each vote
    memset(shuffledVotes, 0, shuffledMaxLen);

    // unseal credentials to obtain the ballot keys
    size_t macLen = sgx_get_add_mac_txt_len((sgx_sealed_data_t*) sealed_data);
    size_t credLen = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) sealed_data);

    uint8_t* cred = (uint8_t*) malloc(credLen);
    sgx_status_t sgx_status = sgx_unseal_data((sgx_sealed_data_t*) sealed_data, NULL, (uint32_t*)&macLen, cred, (uint32_t*)&credLen);
    if (sgx_status != SGX_SUCCESS) {
        printf("ERROR while unsealing sgx_sealed_data - %d\n", sgx_status);
        return;
    }


    // extract the private key from the credentials
    void* ballotPrivateKey;
    sgx_status = sgx_create_rsa_priv1_key(N_LEN, E_LEN, N_LEN, cred, cred+N_LEN, cred+N_LEN+E_LEN+1, &ballotPrivateKey);
    if (sgx_status != SGX_SUCCESS) {
        printf("Something went wrong - %d", sgx_status);
        return;
    }    


    // decrypt the votes using ballot private key
    for (int voteIdx = 0; voteIdx < votesCount; voteIdx++) {

        // encrypt the vote with the ballot's public key
        size_t voteLen = N_LEN;
        uint8_t* vote = (uint8_t*) malloc(voteLen); 
        memset(vote, 0, N_LEN);
        
        sgx_status = sgx_rsa_priv_decrypt_sha256(ballotPrivateKey, vote, &voteLen, votes + voteIdx*VOTE_LEN, N_LEN);
        if (sgx_status != SGX_SUCCESS) {
            printf("Something went wrong.\n");
            return;
        }


        // verify it against the authorized votes
        // vote structure [ voter_public_key (32) ] [ vote ] = (384 bytes)
        if (!isAuthorizedVoter(vote, SGX_SHA256_HASH_SIZE, authorizedVoters, authorizedVotersLen)) {
            continue;
        }

        // exclude (silently) if invalid
        memcpy(shuffledVotes + validVoteCount*(shuffledMaxLen/votesCount), vote+SGX_SHA256_HASH_SIZE, voteLen-SGX_SHA256_HASH_SIZE-1);
        validVoteCount++;       
    }   


    // provide a list of votes in a random order
    if (validVoteCount > 1) {
        uint8_t* tmp = (uint8_t*) malloc(size); 
        size_t i;
        uint16_t* r = (uint16_t*) malloc(validVoteCount);
        sgx_status = sgx_read_rand((uint8_t*) r, validVoteCount*sizeof(uint16_t));

        for (i=0; i<(size_t) validVoteCount; ++i) {
            size_t rnd = (size_t) r[i];
            size_t j = i + rnd / (UINT16_MAX / (validVoteCount-i) + 1);

            memcpy(tmp, shuffledVotes + j * size, size);
            memcpy(shuffledVotes + j *size, shuffledVotes + i * size, size);
            memcpy(shuffledVotes + i * size, tmp, size);
        }
    }



    
    // ocall to export list of votes and print it on the screen
    printf("COLLECTED VOTES:    %d\n", votesCount);
    printf("AUTHORIZED VOTERS:  %d\n", authVotersCount);
    printf("VALID VOTES:        %d\n", validVoteCount);
    printf("\n--VOTING RESULTS--\n");
    for (int i = 0; i<validVoteCount; i++) {        
        printf("%s\n", shuffledVotes + i*size);
    }
    printf("\n");

    
}

void ecall_check_voter(uint8_t* sealed_data, size_t sealed_size, uint8_t* authorizedVoters, size_t authorizedVotersLen, uint8_t* votes, size_t votesLen, uint8_t* check, size_t checkLen) {
    if (sealed_data == NULL || sealed_size <= 0L || authorizedVoters == NULL || authorizedVotersLen <= 0L || votes == NULL || votesLen <= 0L || check == NULL || checkLen <= 0L) {
        return;
    }

    int votesCount = (int) votesLen / (SGX_RSA3072_KEY_SIZE*2);

    // unseal credentials to obtain the ballot keys
    size_t macLen = sgx_get_add_mac_txt_len((sgx_sealed_data_t*) sealed_data);
    size_t credLen = sgx_get_encrypt_txt_len((sgx_sealed_data_t*) sealed_data);

    uint8_t* cred = (uint8_t*) malloc(credLen);
    sgx_status_t sgx_status = sgx_unseal_data((sgx_sealed_data_t*) sealed_data, NULL, (uint32_t*)&macLen, cred, (uint32_t*)&credLen);
    if (sgx_status != SGX_SUCCESS) {
        printf("ERROR while unsealing sgx_sealed_data - %d\n", sgx_status);
        return;
    }


    // extract the private key from the credentials
    void* ballotPrivateKey;
    sgx_status = sgx_create_rsa_priv1_key(N_LEN, E_LEN, N_LEN, cred, cred+N_LEN, cred+N_LEN+E_LEN+1, &ballotPrivateKey);
    free (cred);
    if (sgx_status != SGX_SUCCESS) {
        printf("Something went wrong - %d", sgx_status);
        return;
    }    

    for (int voteIdx = 0; voteIdx < votesCount; voteIdx++) {
        // encrypt the vote with the ballot's public key
        size_t voteLen = N_LEN;
        uint8_t* vote = (uint8_t*) malloc(voteLen); 
        memset(vote, 0, N_LEN);
        
        sgx_status = sgx_rsa_priv_decrypt_sha256(ballotPrivateKey, vote, &voteLen, votes + voteIdx*VOTE_LEN, N_LEN);
        if (sgx_status != SGX_SUCCESS) {
            printf("Something went wrong.\n");
            return;
        }

        // verify if vote was casted
        if (comparePublicKeys(vote, SGX_SHA256_HASH_SIZE, check, checkLen)) {

            // verify if the voter is authorized
            if (!isAuthorizedVoter(vote, SGX_SHA256_HASH_SIZE, authorizedVoters, authorizedVotersLen)) {
                printf("VOTE WAS NOTE COUNTED (unauthorized voter)\n");
                return;
            }

            printf("VOTE WAS TALLIED\n");
            return;
        }
    }   
    
    printf("VOTE NOT CASTED\n");

    return;
   
}


