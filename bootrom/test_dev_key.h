/* These are known device TESTING keys, use them for testing on platforms/qemu */

#warning Using TEST device root key. No integrity guarantee.
static const unsigned char _sanctum_dev_secret_key[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57, 0x6a, 0x9a, 0xb6,
  0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29, 0x85, 0x2f, 0xb9, 0x60,
  0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89, 0xec, 0x06, 0xa8, 0x72, 0x34,
  0x51, 0xaa, 0x0e, 0x4a
};
static const size_t _sanctum_dev_secret_key_len = 64;

static const unsigned char _sanctum_dev_public_key[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96,
  0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46,
  0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};
static const size_t _sanctum_dev_public_key_len = 32;

static const unsigned char _sanctum_cert_root[] = {0x30,0x81,0xe7,0x30,0x81,0x98,0xa0,0x03,0x02,0x01,0x02,0x02,0x03,0x00,0x00,0x00,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x1e,0x17,0x0d,0x32,0x32,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x32,0x33,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x18,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0d,0x52,0x6f,0x6f,0x74,0x20,0x6f,0x66,0x20,0x54,0x72,0x75,0x73,0x74,0x30,0x2c,0x30,0x07,0x06,0x03,0x7b,0x30,0x78,0x05,0x00,0x03,0x21,0x00,0x48,0x39,0x4c,0xc0,0x05,0xc2,0x73,0xd6,0x7d,0x43,0x0c,0x62,0x19,0x76,0x8d,0xec,0xae,0x75,0x1f,0x7b,0xcc,0x3c,0x07,0x01,0x5a,0x1c,0x90,0xd4,0xf9,0x18,0xea,0xe8,0xa3,0x02,0x30,0x00,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x03,0x41,0x00,0x23,0xd2,0x7b,0x23,0x30,0x94,0x67,0x33,0xa2,0x16,0x6f,0x35,0x74,0x55,0xa2,0x45,0xa0,0x65,0x41,0x36,0x67,0x67,0x26,0xbe,0x20,0xb5,0xae,0xc4,0xd8,0x7d,0xa9,0x17,0x92,0x89,0xcc,0xa3,0x71,0x00,0x76,0x04,0xcc,0x77,0xb6,0x35,0x47,0x1d,0x0e,0xef,0x45,0x62,0xcd,0x86,0x63,0x32,0x1a,0x5e,0xa3,0xc2,0x9d,0x44,0xe3,0xe9,0x84,0x0d};
static const size_t _sanctum_length_cert_root = 234;          

static const unsigned char _sanctum_cert_man[] = {0x30,0x81,0xf4,0x30,0x81,0xa5,0xa0,0x03,0x02,0x01,0x02,0x02,0x04,0x00,0xff,0xff,0xff,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x1e,0x17,0x0d,0x32,0x33,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x32,0x34,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x2c,0x30,0x07,0x06,0x03,0x7b,0x30,0x78,0x05,0x00,0x03,0x21,0x00,0x0f,0xaa,0xd4,0xff,0x01,0x17,0x85,0x83,0xba,0xa5,0x88,0x96,0x6f,0x7c,0x1f,0xf3,0x25,0x64,0xdd,0x17,0xd7,0xdc,0x2b,0x46,0xcb,0x50,0xa8,0x4a,0x69,0x27,0x0b,0x4c,0xa3,0x0f,0x30,0x0d,0x30,0x0b,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x01,0x0a,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x03,0x41,0x00,0xc1,0x3b,0x8c,0xa1,0x38,0x56,0xd6,0x95,0xd2,0xac,0xf1,0x42,0xf8,0xe2,0x78,0x48,0x57,0xda,0xfa,0xec,0x03,0xd3,0xfd,0x00,0x21,0xcc,0xaf,0x26,0xe5,0x62,0x8c,0xf0,0xb6,0xca,0x9c,0xf6,0x7a,0x51,0x46,0x18,0x0f,0xeb,0xd2,0x1a,0xda,0x47,0x38,0xc4,0x1a,0x79,0xe4,0x0b,0xcd,0x89,0x41,0x16,0xd6,0xd3,0x5a,0x27,0xd1,0x84,0x77,0x05};
static const size_t _sanctum_length_cert_man = 247;  

/* SCRIPT TO OBATIN _sanctum_cert_man
  /*

  mbedtls_x509write_cert cert_man;
  mbedtls_x509write_crt_init(&cert_man);

  // Setting the name of the issuer of the cert
  
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_man, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_man;
  mbedtls_pk_init(&subj_key_man);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_man;
  mbedtls_pk_init(&issu_key_man);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_man, sanctum_dev_secret_key, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_man, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key_man, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_man[] = {0xFF, 0xFF, 0xFF};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_man, &subj_key_man);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_man, &issu_key_man);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_man, serial_man, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_man, KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_man, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der_man[1024];
  int effe_len_cert_der_man;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_man, cert_der_man, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_man = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_man = cert_der_man;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_man = 1024-effe_len_cert_der_man;
  // cert_real points to the starts of the cert in der format
  cert_real_man += dif_man;

  sanctum_length_cert_man = effe_len_cert_der_man;
  memcpy(sanctum_cert_man, cert_real_man, effe_len_cert_der_man);

*/
////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////
/* SCRIPT TO OBATIN _sanctum_cert_root
  /*
  mbedtls_x509write_cert cert_root;
  mbedtls_x509write_crt_init(&cert_root);

  // Setting the name of the issuer of the cert
  
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert_root, "O=Manufacturer");
  if (ret != 0)
  {
    return 0;
  }
  
  // Setting the name of the subject of the cert
  
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_root, "O=Root of Trust");
  if (ret != 0)
  {
    return 0;
  }

  // pk context used to embed the keys of the subject of the cert
  mbedtls_pk_context subj_key_test;
  mbedtls_pk_init(&subj_key_test);

  // pk context used to embed the keys of the issuer of the cert
  mbedtls_pk_context issu_key_test;
  mbedtls_pk_init(&issu_key_test);
  
  // Parsing the private key of the embedded CA that will be used to sign the certificate of the security monitor
  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_secret_key, 64, 1);
  if (ret != 0)
  {
    return 0;
  }

  ret = mbedtls_pk_parse_public_key(&issu_key_test, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  // Parsing the public key of the security monitor that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key_test, sanctum_device_root_key_pub, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_root[] = {0x00, 0x00, 0x00};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_root, KEYSTONE_SHA3);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20230101000000", "20240101000000");
  if (ret != 0)
  {
    return 0;
  }
  
  unsigned char cert_der_root[1024];
  int effe_len_cert_der_root;

  // The structure mbedtls_x509write_cert is parsed to create a x509 cert in der format, signed and written in memory
  ret = mbedtls_x509write_crt_der(&cert_root, cert_der_root, 1024, NULL, NULL);//, test, &len);
  if (ret != 0)
  {
    effe_len_cert_der_root = ret;
  }
  else
  {
    return 0;
  }

  unsigned char *cert_real_root = cert_der_root;
  // effe_len_cert_der stands for the length of the cert, placed starting from the end of the buffer cert_der
  int dif_root = 1024-effe_len_cert_der_root;
  // cert_real points to the starts of the cert in der format
  cert_real_root += dif_root;

  sanctum_length_cert_root = effe_len_cert_der_root;
  memcpy(sanctum_cert_root, cert_real_root, effe_len_cert_der_root);

*/


