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

static const unsigned char _sanctum_cert_root[] = {0x30,0x81,0xe7,0x30,0x81,0x98,0xa0,0x03,0x02,0x01,0x02,0x02,0x03,
                                                  0x00,0x00,0x00,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x30,0x17,
                                              0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,
                                              0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x1e,0x17,0x0d,0x32,
                                              0x32,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,
                                              0x32,0x33,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,
                                              0x18,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0d,0x52,0x6f,
                                              0x6f,0x74,0x20,0x6f,0x66,0x20,0x54,0x72,0x75,0x73,0x74,0x30,0x2c,0x30,
                                              0x07,0x06,0x03,0x7b,0x30,0x78,0x05,0x00,0x03,0x21,0x00,0x1d,0x24,0x91,
                                              0x2f,0x1f,0x08,0x4a,0xb7,0x47,0x25,0x20,0xf5,0x5b,0x25,0x38,0x98,0xdd,
                                              0x28,0x8c,0x97,0x90,0x6c,0x58,0xa3,0xf7,0xdf,0x39,0xb5,0x09,0x15,0x58,
                                              0x7c,0xa3,0x02,0x30,0x00,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,
                                              0x03,0x41,0x00,0xbe,0xe9,0xd6,0xfe,0x31,0xe8,0xfb,0x17,0x3a,0x9a,0xc6,
                                              0x2a,0xa9,0x9a,0x61,0x4a,0x80,0x05,0x45,0x84,0xf9,0x97,0xdf,0x7f,0xda,
                                              0xe7,0x59,0xe8,0xf3,0x6b,0x44,0xe7,0xa3,0xa6,0x99,0x8b,0x64,0x2c,0x7a,
                                              0x75,0xa5,0x19,0x9a,0x1c,0xf6,0xf9,0xd6,0x72,0x8f,0xde,0xac,0xaa,0xcc,
                                              0xec,0xc0,0x86,0x8a,0xbf,0x9a,0x3c,0x90,0xe9,0x98,0x03};
static const size_t _sanctum_length_cert_root = 234;          

static const unsigned char _sanctum_cert_man[] = {0x30,0x81,0xe7,0x30,0x81,0x98,0xa0,0x03,0x02,0x01,0x02,0x02,0x04,0x00,0xff,0xff,0xff,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x1e,0x17,0x0d,0x32,0x32,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,0x32,0x33,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x17,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x4d,0x61,0x6e,0x75,0x66,0x61,0x63,0x74,0x75,0x72,0x65,0x72,0x30,0x2c,0x30,0x07,0x06,0x03,0x7b,0x30,0x78,0x05,0x00,0x03,0x21,0x00,0x0f,0xaa,0xd4,0xff,0x01,0x17,0x85,0x83,0xba,0xa5,0x88,0x96,0x6f,0x7c,0x1f,0xf3,0x25,0x64,0xdd,0x17,0xd7,0xdc,0x2b,0x46,0xcb,0x50,0xa8,0x4a,0x69,0x27,0x0b,0x4c,0xa3,0x02,0x30,0x00,0x30,0x07,0x06,0x03,0x2b,0x65,0x70,0x05,0x00,0x03,0x41,0x00,0x1c,0x18,0x50,0xaa,0x2c,0xe6,0x44,0x71,0xa5,0x1b,0x14,0x27,0x70,0xb2,0x90,0x48,0xdf,0x9d,0xef,0xfe,0x93,0x08,0xd6,0x9d,0x56,0xd6,0x94,0xb6,0xf4,0x84,0x3d,0xb0,0x49,0x42,0x8b,0xfd,0xfa,0xf6,0xdc,0xe8,0xd0,0x02,0x37,0x91,0x38,0x65,0x85,0x75,0x19,0xd2,0xd3,0x16,0xa7,0xcc,0x99,0xde,0x09,0x83,0x45,0x46,0xec,0xd4,0xc0,0x0a};
static const size_t _sanctum_length_cert_man = 234;  

/* SCRIPT TO OBATIN _sanctum_cert_man
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
  
  ret = mbedtls_x509write_crt_set_subject_name_mod(&cert_root, "O=Manufacturer");
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
  ret = mbedtls_pk_parse_public_key(&subj_key_test, sanctum_dev_public_key, 32, 0);
  if (ret != 0)
  {
    return 0;
  }

  
  // Variable  used to specify the serial of the cert
  unsigned char serial_root[] = {0xFF, 0xFF, 0xFF};
  
  // The public key of the security monitor is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&cert_root, &subj_key_test);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&cert_root, &issu_key_test);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&cert_root, serial_root, 3);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&cert_root, MBEDTLS_MD_SHA512);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20220101000000", "20230101000000");
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
  mbedtls_x509write_crt_set_md_alg(&cert_root, MBEDTLS_MD_SHA512);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&cert_root, "20220101000000", "20230101000000");
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