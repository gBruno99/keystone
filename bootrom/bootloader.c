

#include <stddef.h>


#define ED25519_NO_SEED 1


#include "sha3/sha3.h"
/* Adopted from https://github.com/orlp/ed25519
#include "libsodium_solo_una_dir/crypto_pwhash.h"

  provides:
  - void ed25519_create_keypair(t_pubkey *public_key, t_privkey *private_key, t_seed *seed);
  - void ed25519_sign(t_signature *signature,
                      const unsigned uint8_t *message,
                      size_t message_len,
                      t_pubkey *public_key,
                      t_privkey *private_key);
*/

#include "ed25519/ed25519.h"
/* adopted from
  provides:
  - int sha3_init(sha3_context * md);
  - int sha3_update(sha3_context * md, const unsigned char *in, size_t inlen);
  - int sha3_final(sha3_context * md, unsigned char *out);
  types: sha3_context
*/

#include "string.h"
/*
  provides memcpy, memset
*/

#include "libsodium_solo_una_dir/sodium.h"

/**
 * 
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
*/

//PATH file interni
//home/valerio/keystone/qemu/roms/edk2/CryptoPkg/Library/OpensslLib/openssl/include/openssl/hmac.h
/*
#include <OpensslLib/openssl/include/openssl/hmac.h>
#include <OpensslLib/openssl/include/openssl/kdf.h>
#include <OpensslLib/openssl/include/openssl/evp.h>*/


#define PASSWORD "correct horse battery staple"
#define PASSWORD_LEN 28
#define SALT_SIZE crypto_pwhash_SALTBYTES
#define HASH_SIZE crypto_pwhash_STRBYTES


typedef unsigned char byte;

// Sanctum header fields in DRAM
extern byte sanctum_dev_public_key[32];
extern byte sanctum_dev_secret_key[64];
unsigned int sanctum_sm_size = 0x1ff000;
extern byte sanctum_sm_hash[64];
extern byte sanctum_sm_public_key[32];
extern byte sanctum_sm_secret_key[64];
extern byte sanctum_sm_signature[64];

/*
extern byte device_root_key_priv[64];
extern byte device_root_key_pub[64];

extern byte sign_sm[64];
extern byte pub_key_manufacturer[64];

extern byte compound_devide_identifier[64];

extern byte sm_signature_drk[64];
*/
#define DRAM_BASE 0x80000000

/* Update this to generate valid entropy for target platform*/
inline byte random_byte(unsigned int i) {
#warning Bootloader does not have entropy source, keys are for TESTING ONLY
  return 0xac + (0xdd ^ i);
}

void bootloader() {
	//*sanctum_sm_size = 0x200;
  // Reserve stack space for secrets
  byte scratchpad[128];
  sha3_ctx_t hash_ctx;

  byte device_root_key_priv[64];
  byte device_root_key_pub[64];

  byte sign_sm[64];
  byte pub_key_manufacturer[64];

  byte compound_devide_identifier[64];

  byte sm_signature_drk[64];

  byte eca_key_priv[64];
  byte eca_key_pub[64];
  



  // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
  // ... SD card to beginning of memory.
  // sd_init();
  // sd_read_from_start(DRAM, 1024);

  /* Gathering high quality entropy during boot on embedded devices is
   * a hard problem. Platforms taking security seriously must provide
   * a high quality entropy source available in hardware. Platforms
   * that do not provide such a source must gather their own
   * entropy. See the Keystone documentation for further
   * discussion. For testing purposes, we have no entropy generation.
  */

  // Create a random seed for keys and nonces from TRNG
  for (unsigned int i=0; i<32; i++) {
    scratchpad[i] = random_byte(i);
  }

  /* On a real device, the platform must provide a secure root device
     keystore. For testing purposes we hardcode a known private/public
     keypair */
  // TEST Device key
  #include "use_test_keys.h"
  
  // From the unique device identifier, a keypair is created, the device root key
  ed25519_create_keypair(device_root_key_pub, device_root_key_priv, sanctum_dev_secret_key);


  // Loading of the manufacturer public key and of the digital signature of the security monitor
  


  // Measure SM
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, (void*)DRAM_BASE, sanctum_sm_size);
  sha3_final(sanctum_sm_hash, &hash_ctx);

  //Verify the signature of the security monitor provided by the manufacturer
  if(ed25519_verify(sign_sm, (void*)DRAM_BASE, sanctum_sm_size ,pub_key_manufacturer)){
    
    // All ok

    // Combine hash of the security monitor and the device root key to obtain the CDI
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, device_root_key_priv, sizeof(*device_root_key_priv));
    sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
    sha3_final(compound_devide_identifier, &hash_ctx);

    // Using the CDI a new keypair is derived for the attestation 


    // The measure of the sm is signed with the device root key
    ed25519_sign(sm_signature_drk, sanctum_sm_hash, sizeof(*sanctum_sm_hash), device_root_key_pub, device_root_key_priv);

    // Generating the key associated to the embedded CA
    ed25519_create_keypair(eca_key_pub, eca_key_priv, device_root_key_priv);



  }
  else{
    // The security monitor cannot be verified -> exit
  }


  // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
  //ed25519_create_keypair(sanctum_dev_public_key, sanctum_dev_secret_key, scratchpad);


  // Combine SK_D and H_SM via a hash
  // sm_key_seed <-- H(SK_D, H_SM), truncate to 32B
  sha3_init(&hash_ctx, 64);
  sha3_update(&hash_ctx, sanctum_dev_secret_key, sizeof(*sanctum_dev_secret_key));
  sha3_update(&hash_ctx, sanctum_sm_hash, sizeof(*sanctum_sm_hash));
  sha3_final(scratchpad, &hash_ctx);
  // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
  ed25519_create_keypair(sanctum_sm_public_key, sanctum_sm_secret_key, scratchpad);

  // Endorse the SM
  memcpy(scratchpad, sanctum_sm_hash, 64);
  memcpy(scratchpad + 64, sanctum_sm_public_key, 32);
  // Sign (H_SM, PK_SM) with SK_D
  ed25519_sign(sanctum_sm_signature, scratchpad, 64 + 32, sanctum_dev_public_key, sanctum_dev_secret_key);

  // Clean up
  // Erase SK_D
  memset((void*)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));

  // Erase DRK_priv
  memset((void*)device_root_key_priv, 0, sizeof(*device_root_key_priv));

  // Erase CDI
  memset((void*)compound_devide_identifier, 0, sizeof(*compound_devide_identifier));

  // Erase eca_key_priv
  memset((void*)eca_key_priv, 0, sizeof(*eca_key_priv));

  return;
}