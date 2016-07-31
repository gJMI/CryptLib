#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

int main ()
{
  int err;
  int sig_len;
  unsigned char sig_buf [4096];
  static char certfile[] = "C:\\temp\\radislav.cer"; //"cert.pem"
  static char keyfile[]  = "c:\\temp\\radislav.key"; //"key.pem"
  static char data[]     = "I owe you...";
  EVP_MD_CTX     md_ctx;
  EVP_PKEY *      pkey;
  FILE *          fp;
  FILE			  *fw;
  X509 *	x509;

  /* Just load the crypto library error strings,
   * SSL_load_error_strings() loads the crypto AND the SSL ones */
  /* SSL_load_error_strings();*/
  ERR_load_crypto_strings();
  
  /* Read private key */
  
  fp = fopen (keyfile, "r");
  if (fp == NULL) exit (1);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose (fp);

  if (pkey == NULL) { 
	ERR_print_errors_fp (stderr);
	exit (1);
  }
  
  /* Do the signature */
  
  EVP_SignInit   (&md_ctx, EVP_sha1());
  EVP_SignUpdate (&md_ctx, data, strlen(data));
  sig_len = sizeof(sig_buf);
  err = EVP_SignFinal (&md_ctx, sig_buf, &sig_len, pkey);

  if (err != 1) {
	ERR_print_errors_fp(stderr);
	exit (1);
  }

  EVP_PKEY_free (pkey);
  
  fw=fopen ("signed.out", "w");
  fputs(sig_buf,fw);
  fclose(fw);
  
  /* Read public key */
  
  fp = fopen (certfile, "r");
  if (fp == NULL) exit (1);
  x509 = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose (fp);

  if (x509 == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }
  
  /* Get public key - eay */
  pkey=X509_get_pubkey(x509);
  if (pkey == NULL) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }

  /* Verify the signature */
  
  EVP_VerifyInit   (&md_ctx, EVP_sha1());
  EVP_VerifyUpdate (&md_ctx, data, strlen((char*)data));
  err = EVP_VerifyFinal (&md_ctx, sig_buf, sig_len, pkey);
  EVP_PKEY_free (pkey);

  if (err != 1) {
	ERR_print_errors_fp (stderr);
	exit (1);
  }
  printf ("Signature Verified Ok.\n");
  return(0);
}