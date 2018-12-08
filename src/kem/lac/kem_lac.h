#ifndef __OQS_KEM_LAC_H
#define __OQS_KEM_LAC_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_lac_512_cca_kem

#define OQS_KEM_lac_512_cca_kem_length_public_key 544
#define OQS_KEM_lac_512_cca_kem_length_secret_key (512+544)
#define OQS_KEM_lac_512_cca_kem_length_ciphertext 1024
#define OQS_KEM_lac_512_cca_kem_length_shared_secret 32

OQS_KEM *OQS_KEM_lac_512_cca_kem_new();

OQS_STATUS OQS_KEM_lac_512_cca_kem_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS OQS_KEM_lac_512_cca_kem_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_STATUS OQS_KEM_lac_512_cca_kem_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);

#endif


#endif // __OQS_KEM_LAC_H
