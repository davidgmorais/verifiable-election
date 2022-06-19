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

void ecall_gen_credentials(char* passwd) {
    if (passwd == NULL) return;

    uint8_t* n = (uint8_t*) malloc(N_LEN);
    uint8_t* d = (uint8_t*) malloc(N_LEN);
    long e = 65537;

    uint8_t* p = (uint8_t*) malloc(N_LEN);
    uint8_t* q = (uint8_t*) malloc(N_LEN);

    uint8_t* dmp1 = (uint8_t*) malloc(N_LEN);
    uint8_t* dmq1 = (uint8_t*) malloc(N_LEN);
    uint8_t* iqmp = (uint8_t*) malloc(N_LEN);

    // generate RSA key pair to act as credentials
    sgx_status_t status = sgx_create_rsa_key_pair(N_LEN, E_LEN, n, d, (unsigned char*)&e, p, q, dmp1, dmq1, iqmp);
    if (status != SGX_SUCCESS) {
        printf("ERROR on the creation of the key pairs %d\n", status);
        return;
    }

    free(p);
    free(q);
    free(dmp1);
    free(dmq1);
    free(iqmp);

    size_t pubKeyLen = (N_LEN+E_LEN) * sizeof(uint8_t);
    uint8_t* pubKey = (uint8_t*) malloc(pubKeyLen);
    memcpy(pubKey, n, N_LEN);
    memcpy(pubKey+N_LEN, (unsigned char*)&e, E_LEN);


    // hash to create identifier for brevity
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t hash;

    status = sgx_sha256_init(&sha_context);
    if (status != SGX_SUCCESS) {
        return;
    } 

    status = sgx_sha256_update((const uint8_t*) &pubKey[0], 194, sha_context);
    if (status != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return;
    }

    status = sgx_sha256_update((const uint8_t*) &pubKey[194], 194, sha_context);
    if (status != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return;
    }

    status = sgx_sha256_get_hash(sha_context, &hash);
    if (status != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return;
    }
    status = sgx_sha256_close(sha_context);


    size_t credLen = SGX_SHA256_HASH_SIZE + E_LEN + 2*N_LEN * sizeof(uint8_t) + 1; 
    uint8_t* cred = (uint8_t*) malloc(credLen);

    memcpy(cred, hash, SGX_SHA256_HASH_SIZE);
    cred[pubKeyLen] = (uint8_t) '\n';
    // according to the struct _sgx_rsa3072_key_t [ mod ] [ d ] [ e ]
    memcpy(cred+SGX_SHA256_HASH_SIZE+1, n, N_LEN);
    memcpy(cred+SGX_SHA256_HASH_SIZE+1+N_LEN, d, N_LEN);
    memcpy(cred+SGX_SHA256_HASH_SIZE+1+2*N_LEN, (unsigned char*)&e, E_LEN);
    free(d);
    free(n);

    // get signing key based on the provided password
    uint8_t* key = (uint8_t*) malloc(SGX_AESGCM_KEY_SIZE); 
    size_t sealed_size = credLen + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);

    char salt = 0;
    status = ocall_derive_key(key, SGX_AESGCM_KEY_SIZE, salt, passwd);
    if (status != SGX_SUCCESS) {
       return;
    }
    status = sgx_read_rand(sealed_data, SGX_AESGCM_IV_SIZE);
    if (status != SGX_SUCCESS) {
        return;
    } 


    // seal the data 
    // output on the format [ IV (12 bytes) ] [ SEALED_DATA ] [ MAC (16 bytes) ]
    status = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*) key, 
        cred, (uint32_t) credLen, 
        sealed_data + SGX_AESGCM_IV_SIZE, 
        sealed_data, SGX_AESGCM_IV_SIZE, 
        NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*) (sealed_data + SGX_AESGCM_IV_SIZE + credLen)
    );
    free(key);
    if (status != SGX_SUCCESS) {
        return;
    }

    ocall_write_file(sealed_data, sealed_size, "../creds", ".seal");
    free(sealed_data);
    free(cred);    
}

void ecall_unseal_and_export_pub(uint8_t* sealed, size_t sealedLen, char* password) {
    if (sealed == NULL || sealedLen <= 0L || password == NULL) return;

    // get signing key based on the provided password
    uint8_t* key = (uint8_t*) malloc(SGX_AESGCM_KEY_SIZE); 
    size_t credLen = sealedLen - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    uint8_t* cred = (uint8_t*) malloc(credLen); 

    sgx_status_t sgx_status = ocall_derive_key(key, SGX_AESGCM_KEY_SIZE, 0, password);
    if (sgx_status != SGX_SUCCESS) {
        return;
    }


    // unseal the data
    sgx_status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*) key, 
        sealed + SGX_AESGCM_IV_SIZE, (uint32_t) credLen,
        cred,
        sealed, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*) (sealed + credLen + SGX_AESGCM_IV_SIZE)
    );
    free(key);
    if (sgx_status != SGX_SUCCESS) {
        printf("Failed to unseal data\n");
        return;
    }


    size_t pubKeyLen = SGX_SHA256_HASH_SIZE;
    uint8_t* pubKey = (uint8_t*) malloc(pubKeyLen);
    memcpy(pubKey, cred, pubKeyLen);
    free(cred);

    // expot to the outside
    ocall_write_file(pubKey, pubKeyLen, "../keys", "");
    free(pubKey);
}

void ecall_produce_vote(char* vote, uint8_t* sealed_data, size_t sealed_size, char* password, uint8_t* pubKey, size_t pubKeyLen) {
    if (vote == NULL || sealed_data == NULL || sealed_size <= 0L || password == NULL || pubKey == NULL || pubKeyLen <= 0L) return;

    if (strlen(vote) >= (N_LEN + SGX_AESGCM_IV_SIZE)) {
        printf("Provided vote is too big.");
    }

    // get signing key based on the provided password
    uint8_t* key = (uint8_t*) malloc(SGX_AESGCM_KEY_SIZE); 
    size_t credLen = sealed_size - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
    uint8_t* cred = (uint8_t*) malloc(credLen); 

    sgx_status_t sgx_status = ocall_derive_key(key, SGX_AESGCM_KEY_SIZE, 0, password);
    if (sgx_status != SGX_SUCCESS) {
        return;
    }

    // unseal the data
    sgx_status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*) key, 
        sealed_data + SGX_AESGCM_IV_SIZE, (uint32_t) credLen,
        cred,
        sealed_data, SGX_AESGCM_IV_SIZE,
        NULL, 0,
        (const sgx_aes_gcm_128bit_tag_t*) (sealed_data + credLen + SGX_AESGCM_IV_SIZE)
    );
    if (sgx_status != SGX_SUCCESS) {
        printf("Failed to unseal data\n");
        return;
    }

    // extract the voter's keys
    uint8_t* voterPublicKey = (uint8_t*) malloc(SGX_SHA256_HASH_SIZE);
    memcpy(voterPublicKey, cred, SGX_SHA256_HASH_SIZE);

    size_t voterPrivateKeyLen = credLen - SGX_SHA256_HASH_SIZE - 1;
    uint8_t* voterPrivateKey = (uint8_t*) malloc(voterPrivateKeyLen);
    memcpy(voterPrivateKey, cred + SGX_SHA256_HASH_SIZE + 1, voterPrivateKeyLen);


    void* ballotPublicKey;
    sgx_status = sgx_create_rsa_pub1_key(N_LEN, E_LEN, pubKey, pubKey+N_LEN, &ballotPublicKey);
    if (sgx_status != SGX_SUCCESS) {
        printf("Something went wrong - %d", sgx_status);
        return;
    }


    // generate vote [ voter_id (32) ] [ vote ]
    size_t identifiableVoteLen = SGX_SHA256_HASH_SIZE + strlen(vote) + 1;
    uint8_t* identifiableVote = (uint8_t*) malloc(identifiableVoteLen);
    memcpy(identifiableVote, voterPublicKey, SGX_SHA256_HASH_SIZE);
    memcpy(identifiableVote + SGX_SHA256_HASH_SIZE, vote, strlen(vote));
    identifiableVote[identifiableVoteLen] = 0;


    // encrypt the vote with the ballot's public key
    size_t dst_len = N_LEN;
    uint8_t* encryptedVote = (uint8_t*) malloc(dst_len);
    
    sgx_status = sgx_rsa_pub_encrypt_sha256(ballotPublicKey, encryptedVote, &dst_len, identifiableVote, identifiableVoteLen);
    if (sgx_status != SGX_SUCCESS) {
        printf("Something went wrong.");
        return;
    }

    // sign the encription with the voter's private key
    uint8_t* signature = (uint8_t*) malloc(sizeof(sgx_rsa3072_signature_t));
    sgx_status = sgx_rsa3072_sign(encryptedVote, (uint32_t) dst_len, (sgx_rsa3072_key_t*) voterPrivateKey, (sgx_rsa3072_signature_t*)signature);
    if (sgx_status != SGX_SUCCESS) {
        printf("Signing failed");
        return;
    }
 

    // cast the vote with the structure [ encrypted_vote ] [ signature ]
    size_t signedVoteLen = dst_len + sizeof(sgx_rsa3072_signature_t);
    uint8_t* signedVote = (uint8_t*) malloc(signedVoteLen);
    memcpy(signedVote, encryptedVote, dst_len);
    memcpy(signedVote + dst_len, signature, sizeof(sgx_rsa3072_signature_t));

    ocall_write_file(signedVote, signedVoteLen, "../votes", ".vote");
   
}
