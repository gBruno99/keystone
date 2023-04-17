//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "pmp.h"
#include "crypto.h"
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include "sha3/sha3.h"

#include "x509custom.h"
#define DRAM_BASE 0x80000000

static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;

/* from Sanctum BootROM */
extern byte sanctum_sm_hash[MDSIZE];
extern byte sanctum_sm_signature[SIGNATURE_SIZE];
extern byte sanctum_sm_secret_key[PRIVATE_KEY_SIZE];
extern byte sanctum_sm_public_key[PUBLIC_KEY_SIZE];
extern byte sanctum_dev_public_key[PUBLIC_KEY_SIZE];



extern byte sanctum_CDI[64];
extern byte sanctum_ECASM_pk[64];
extern byte sanctum_device_root_key_pub[64];
extern byte sanctum_cert_sm[256];
extern int sanctum_length_cert;

byte CDI[64] = { 0, };
byte ECASM_pk[64] = { 0, };
byte device_root_key_pub[64] = {0,};
byte cert_sm[256] = { 0, };
byte length_cert;

byte ECASM_priv[64];
mbedtls_x509_crt uff_cert_sm;

//extern byte sanctum_sm_hash_to_check[64];

// the pk of the ECA is only 32bytes, but according to the alignment of the memory, it has to be of 64 bytes
/*
* Variable used to verify that the public key of the sm created during the boot is the same key obtained after the
* parsing of the certificate in der format
*/
//extern byte sanctum_sm_key_pub[64];
//extern byte sanctum_ECA_pk[64];



//extern byte sanctum_sm_signature_drk[64];


byte sm_hash[MDSIZE] = { 0, };
byte sm_signature[SIGNATURE_SIZE] = { 0, };
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0, };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0, };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0, };

//byte sm_hash_to_check[64] = { 0, };
//byte sm_key_pub[64] = { 0, };
//byte sm_signature_drk[64] = {0,};
//


byte hash_for_verification[64];
sha3_ctx_t ctx_hash;

// Variable used for testing porpouse to pass data from the boot stage to the sm
extern byte test[64];

unsigned int sanctum_sm_size = 0x1ff000;


char* validation(mbedtls_x509_crt cert);

int osm_pmp_set(uint8_t perm)
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  return pmp_set_keystone(os_region_id, perm);
}

int smm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP, &region, 0);
  if(ret)
    return -1;

  return region;
}

int osm_init()
{
  int region = -1;
  int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
  if(ret)
    return -1;

  return region;
}

void sm_sign(void* signature, const void* data, size_t len)
{
  sign(signature, data, len, sm_public_key, sm_private_key);
}

int sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash)
{
  unsigned char info[MDSIZE + key_ident_size];

  sbi_memcpy(info, enclave_hash, MDSIZE);
  sbi_memcpy(info + MDSIZE, key_ident, key_ident_size);

  /*
   * The key is derived without a salt because we have no entropy source
   * available to generate the salt.
   */
  return kdf(NULL, 0,
             (const unsigned char *)sm_private_key, PRIVATE_KEY_SIZE,
             info, MDSIZE + key_ident_size, key, SEALING_KEY_SIZE);
}

void sm_copy_key()
{
  sbi_memcpy(sm_hash, sanctum_sm_hash, MDSIZE);
  sbi_memcpy(sm_signature, sanctum_sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(sm_public_key, sanctum_sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(sm_private_key, sanctum_sm_secret_key, PRIVATE_KEY_SIZE);
  sbi_memcpy(dev_public_key, sanctum_dev_public_key, PUBLIC_KEY_SIZE);
  
  sbi_printf("Data obtained from the booting stage:\n");

  sbi_memcpy(ECASM_pk, sanctum_ECASM_pk, 64);
  sbi_memcpy(CDI, sanctum_CDI, 64);
  //sbi_memcpy(sm_hash_to_check, sanctum_sm_hash_to_check, 64);
  sbi_memcpy(cert_sm, sanctum_cert_sm, sanctum_length_cert);
  sbi_memcpy(device_root_key_pub, sanctum_device_root_key_pub, 64);
  //sbi_memcpy(sm_signature_drk, sanctum_sm_signature_drk, 64);
  sbi_memcpy(device_root_key_pub, sanctum_device_root_key_pub, 64);
  length_cert = sanctum_length_cert;

  sbi_printf("CDI:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", CDI[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  sbi_printf("ECASM_pk:\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", ECASM_pk[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  /*
  sbi_printf("sm_hash_to_check:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", sm_hash_to_check[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");*/
  /*
  sbi_printf("sm_signature_drk:\n");
  for(int i = 0; i < 64; i ++){
    sbi_printf("%02x", sm_signature_drk[i]);
  }
  sbi_printf("\n-------------------------------------------------\n"); */
  sbi_printf("device_root_key_pub:\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", device_root_key_pub[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  
  sbi_printf("length_cert:");
  sbi_printf("%d", length_cert);
  sbi_printf("\n-------------------------------------------------\n");

  sbi_printf("cert der format:\n");
  for(int i = 0; i < length_cert; i ++){
    sbi_printf("%02x", cert_sm[i]);
  }
  sbi_printf("\n-------------------------------------------------\n");
  
  if ((mbedtls_x509_crt_parse_der(&uff_cert_sm, cert_sm, length_cert)) != 0){
      sbi_printf("\n\n\n[SM] Error parsing the certificate created during the booting process");
      sbi_hart_hang();
  }
  else{
    sbi_printf("\n\n\n[SM] The certificate of the security monitor is correctly parsed\n\n");

  }

  sbi_printf("Signature of the certificate: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",uff_cert_sm.sig.p[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");

  char* str_ret = validation(uff_cert_sm);
  if(my_strlen(str_ret) != 0){
    sbi_printf("[SM] Problem with the certificate: %s \n", str_ret);
    sbi_hart_hang();

  }
  else 
    sbi_printf("[SM] The certificate is formally correct, now let's verify the signature\n");


 
  /**
   * Computing the hash to verify the signature of the certificate
   * 
  */
  
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, uff_cert_sm.tbs.p, uff_cert_sm.tbs.len);
  sha3_final(hash_for_verification, &ctx_hash);
  //hash_for_verification[0] = 0x23;

  /*
  *
  * Test used to check if the hash obtained from parsing the cert in the der format
  * is the same of the hash computed during the creation of the cert in der format to sign it
  * 
  sbi_printf("hash_for_verification: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",hash_for_verification[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  sbi_printf("test: \n");
    for(int i =0; i <64; i ++){
        sbi_printf("%02x",test[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n\n\n\n");
  */

  
  /**
   * Verifying the signature
   * 
  */
  if(ed25519_verify(uff_cert_sm.sig.p, hash_for_verification, 64, device_root_key_pub) == 0){
    sbi_printf("[SM] Error verifying the signature of the certificate\n");
    sbi_hart_hang();
  }
  else{
    sbi_printf("[SM] The signature of the certificate is ok\n");

  }

  /**
   * Checking the measure made by the boot of the SM
   */
    /*
    sha3_init(&ctx_hash, 64);
    sha3_update(&ctx_hash, (void *)DRAM_BASE, sanctum_sm_size);
    sha3_final(hash_for_verification, &ctx_hash);
  */

    /*
    if ((ed25519_verify(sm_signature_drk, sm_hash_to_check, 64, device_root_key_pub)) == 0)
    {
      sbi_printf("[SM] Error verifying the signature of the SM measure made during the boot\n");
      sbi_hart_hang();
    }
    else
    {
      sbi_printf("[SM] The signature of the SM measure made during the boot is correct\n\n");
    }
    */

  ed25519_create_keypair(ECASM_pk, ECASM_priv, CDI);


  /*
  * To check that the data read from the certificate is the correct one created in the booting stage
  */
  ///////////////////////////////////////////////////////////////////////////////
  sbi_printf("-----------------------------------------------------------------------------------------\n");
  sbi_printf("Comparing what is parsed from the cert and what is directly passed from the booting stage\n");
  sbi_printf("-----------------------------------------------------------------------------------------\n");
  sbi_printf("sanctum_sm_key_pub from the booting stage\n");
  for(int i = 0; i < 32; i ++){
    sbi_printf("%02x", ECASM_pk[i]);
  }
  sbi_printf("\n\n");
  sbi_printf("sanctum_sm_key_pub obtained parsing the der format cert\n");
    for(int i =0; i <32; i ++){
        sbi_printf("%02x",uff_cert_sm.pk.pk_ctx.pub_key[i]);//   pk_ctx->pub_key[i]);
    }
  sbi_printf("\n");
  sbi_printf("-----------------------------------------------------------------------------------------\n");

  ////////////////////////////////////////////////////////////////////////////////
  

}

void sm_print_hash()
{ 
  /*
  sbi_printf("SM HASH\n-------------------------------------------------\n");
  for (int i=0; i<MDSIZE; i++)
  {
    sbi_printf("%02x", (char) sm_hash[i]);
  }
  sbi_printf("\n");

  */
}

/*
void sm_print_cert()
{
	int i;

	printm("Booting from Security Monitor\n");
	printm("Size: %d\n", sanctum_sm_size[0]);

	printm("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		printm("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");

	printm("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		printm("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");
}
*/

void sm_init(bool cold_boot)
{
	// initialize SMM
  if (cold_boot) {
    /* only the cold-booting hart will execute these */
    sbi_printf("[SM] Initializing ... hart [%lx]\n", csr_read(mhartid));
    

    sbi_ecall_register_extension(&ecall_keystone_enclave);

    sm_region_id = smm_init();
    
    mbedtls_x509_crt_init(&uff_cert_sm);

    if(sm_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize SM memory");
      sbi_hart_hang();
    }

    os_region_id = osm_init();
    if(os_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize OS memory");
      sbi_hart_hang();
    }

    if (platform_init_global_once() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM] platform global init fatal error");
      sbi_hart_hang();
    }
    // Copy the keypair from the root of trust
    sm_copy_key();

    //sbi_memset(&uff_cert, 0, sizeof(mbedtls_x509_crt));

    // Init the enclave metadata
    enclave_init_metadata();

    //sm_print_hash();

    sm_init_done = 1;
    mb();
  }

  /* wait until cold-boot hart finishes */
  while (!sm_init_done)
  {
    mb();
  }

  /* below are executed by all harts */
  pmp_init();
  pmp_set_keystone(sm_region_id, PMP_NO_PERM);
  pmp_set_keystone(os_region_id, PMP_ALL_PERM);

  /* Fire platform specific global init */
  if (platform_init_global() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM] platform global init fatal error");
    sbi_hart_hang();
  }

  sbi_printf("[SM] Keystone security monitor has been initialized!\n");

  sm_print_hash();

  return;
  // for debug
  // sm_print_cert();
}

char* validation(mbedtls_x509_crt cert){

  if(cert.ne_issue_arr == 0)
    return "Problem with the issuer of the certificate";
  if(cert.ne_subje_arr == 0)
    return "Problem with the subject of the certificate";
  if((cert.valid_from.day == 0) || (cert.valid_from.mon == 0) || (cert.valid_from.day == 0))
    return "Problem with the valid_from field of the certificate";
  if((cert.valid_to.day == 0) || (cert.valid_to.mon == 0) || (cert.valid_to.day == 0))
    return "Problem with the valid_to field of the certificate";
  if(cert.pk.pk_ctx.len != 32)
    return "Problem with the pk length of the certificate";
  if(cert.serial.len == 0)
    return "Problem with the serial length of the certificate";
  if(cert.sig.len == 0)
    return "Problem with the signature length of the certificate";
  return "";

}
