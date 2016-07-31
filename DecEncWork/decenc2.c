// PKCS7_DETACHED | PKCS7_STREAM | PKCS7_BINARY | PKCS7_CRLFEOL


#include <stdio.h>

#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h> 

int main ()
{
  PKCS7 *pk,*pk_data,*pke;
  PKCS7_SIGNER_INFO *si;
  X509 *x509,*x509srv;
  EVP_PKEY *pkey;
  static char keyfile[]  = "c:\\temp\\radislav.key";
  static char certfile[] = "C:\\temp\\radislav.der";
  static char inputfile[] = "c:\\temp\\JPU_yellow_in.p7m";
  static char outputfile[] = "c:\\temp\\JPU_yellow.p7m";
  static char outputfileenc[] = "c:\\temp\\JPU_yellow2.p7m";
  static char outputfileenc2[] = "c:\\temp\\JPU_yellow4.p7m";
  static char servercertfile[] = "c:\\temp\\csas_at.cer";
  static char data2[8192];
  static char radka[51],radka2[sizeof(char)*1000+1];
  FILE *fp,*fr;
  BIO *data;
  BIO *pkBIO,*pkBIOin,*p7bio;
  FILE *fout;
  BIO *out;
  char buf[1024*4],*test;
  int i,j=0,delka=0,pos=0;
  EVP_MD_CTX md_ctx;

  ERR_load_crypto_strings();  
  
  printf("Size of CHAR %i\n",sizeof(char));
  
// Private key read

  fp = fopen (keyfile, "r");
  if (fp == NULL) exit (1);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose (fp);

  if (pkey == NULL)
  { 
	ERR_print_errors_fp (stderr);
	exit (1);
  }

// public cert read
  fp = fopen (certfile, "rb");
  if (fp == NULL) exit (1);
//  x509 = PEM_read_X509(fp, NULL, NULL, NULL);
  x509 = d2i_X509_fp(fp,NULL);
  fclose (fp);
  if (x509 == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }

//TODO: �ten� BIO memory + doplnit za��tek a konec, pak p�e��st PEM x509
  /*
  	if ((in=BIO_new_file("server.pem","r")) == NULL) goto err;
	if ((x509=PEM_read_bio_X509(in,NULL,NULL,NULL)) == NULL) goto err;
  */
// data to sign read
  
  strcpy(data2,"");

  fr=fopen(inputfile,"r");

  while (!feof(fr)) {
    if((fgets(radka,50,fr))!=NULL)
	  if(strstr(radka,"PKCS7") == NULL)
	    strcat(data2,radka);

    if (ferror(fr)) {
	  printf("Error reading file");;
	  return(1);
    }      
  };


// PKCS7 structure

  EVP_add_digest(EVP_sha1());
 
  pk=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_signed);

/*
//  PKCS7_set0_type_other(pk, NID_pkcs7_data, V_ASN1_OCTET_STRING);

  pk_data=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_enveloped);

  pkBIO=PKCS7_dataInit(pk_data,NULL);
  
  if (pkBIO == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }

  BIO_puts(pkBIO,data2);
  PKCS7_dataFinal(pk_data,pkBIO);

  PKCS7_set_content(pk, pk_data);
*/  



  si=PKCS7_add_signature(pk,x509,pkey,EVP_sha1());
  //time
  PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,OBJ_nid2obj(NID_pkcs7_data));
  PKCS7_add_certificate(pk,x509);

  PKCS7_content_new(pk,NID_pkcs7_data);
  pkBIO=PKCS7_dataInit(pk,NULL);
  if (pkBIO == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }
  BIO_write(pkBIO,data2,strlen(data2));
  PKCS7_dataFinal(pk,pkBIO);
  ERR_print_errors_fp (stderr);
  BIO_free(pkBIO);

/*
    data=BIO_new_file(inputfile, "rb");
	pk=PKCS7_sign(x509,pkey, NULL, data, PKCS7_TEXT| PKCS7_NOSMIMECAP | PKCS7_NOATTR | PKCS7_NOOLDMIMETYPE | PKCS7_CRLFEOL);
*/

  if (pk == NULL)
  { 
	ERR_print_errors_fp (stderr);	
	exit (1);
  }

  PEM_write_PKCS7(stdout,pk);

  fp = fopen (outputfile, "w");
  if (fp == NULL) exit (1);
//  PEM_write_PKCS7(fp,pk);
  

//  fout = fopen(outputfile,"wb+");
//  out = BIO_new(BIO_s_file());
  out = BIO_new(BIO_s_mem());
//  BIO_set_fp(out, fout, BIO_NOCLOSE);
  ERR_print_errors_fp (stderr);
  i2d_PKCS7_bio(out, pk);
  ERR_print_errors_fp (stderr);
//  fclose(fout); 

  fclose(fp);

  
   
  

//  BIO_free(data);
  PKCS7_free(pk);

// Encrypt

  EVP_add_cipher(EVP_des_ede3_cbc());

// public cert read
  fp = fopen (servercertfile, "rb");
  if (fp == NULL) exit (1);
  x509srv = PEM_read_X509(fp, NULL, NULL, NULL);
//  x509srv = d2i_X509_fp(fp,NULL);
  fclose (fp);
  if (x509srv == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }

// input file

  pkBIOin=BIO_new_file(outputfile,"rb");

//  pke=PKCS7_encrypt(x509srv, pkBIOin, EVP_des_ede3_cbc(),PKCS7_BINARY);

	pke = PKCS7_new();

	PKCS7_set_type(pke, NID_pkcs7_enveloped);
    PKCS7_set_cipher(pke, EVP_des_ede3_cbc());

	PKCS7_add_recipient(pke, x509srv);


    p7bio = PKCS7_dataInit(pke, NULL);

 //	SMIME_crlf_copy(pkBIOin, p7bio, NULL);

  strcpy(data2,"");

  fr=fopen(outputfile,"rb");

  while (!feof(fr)) {
    if((j=fread(data2,sizeof(char),8190,fr))>0)

    if (ferror(fr)) {
	  printf("Error reading file");;
	  return(1);
    }      
  };
  printf("Strlen data2: %i\n",strlen(data2));
  printf("Strlen data2: %i\n",j);

//  BIO_write(p7bio,data2,j);
//  BIO_flush(p7bio);
  delka=(BIO_ctrl_pending(out))/sizeof(char); //ulo�en char
  test=(char*)malloc(sizeof(char)*delka);
  pos=0;
  j=0;
  while((j=BIO_read(out,radka2,1000))>0)
  {
    BIO_write(p7bio,radka2,j);
	for(i=0;i<j;i++)
	{
	  test[i+pos]=radka[i];
	}
	pos+=j;
  }
  printf("Copied %i bytes",delka);
  BIO_flush(p7bio);
  PKCS7_dataFinal(pke,p7bio);
  ERR_print_errors_fp(stderr);
  BIO_free(p7bio);
  BIO_free(out);

//	BIO_free_all(p7bio);
  PEM_write_PKCS7(stdout,pke);
  fp = fopen (outputfileenc, "wb");
  if (fp == NULL) exit (1);
  PEM_write_PKCS7(fp,pke); 
  fclose(fp);

  out = BIO_new_file(outputfileenc2, "w");
  PEM_write_bio_PKCS7(out,pke);
// BIO_ctrl_pending(out);
  printf("BIO pending: %i",j);
  BIO_flush(out);
  BIO_free(out);


//TODO int PEM_ASN1_write_bio( --> z�pis do BIO

/*  strcpy(data2,"");

  fr=fopen(inputfile,"r");

  while (!feof(fr)) {
    if((fgets(radka,50,fr))!=NULL)
	  if(strstr(radka,"PKCS7") == NULL)
	    strcat(data2,radka);

    if (ferror(fr)) {
	  printf("Error reading file");;
	  return(1);
    }      
  };
*/
  free(test);
  return(15);
}