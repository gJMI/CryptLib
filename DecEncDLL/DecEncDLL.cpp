// DecEncDLL.cpp : Defines the exported functions for the DLL application.
// uses: C:\WINDOWS\WinSxS\x86_Microsoft.VC90.CRT_1fc8b3b9a1e18e3b_9.0.30729.1_x-ww_6f74963e\msvcr90.dll

#include "stdafx.h"
#include <stdio.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h> 
#include <openssl/pem.h>
#include <openssl/sha.h>

#define CHECK(x) if((x)==NULL) return(__LINE__);

#define dgstSHA1	0
#define dgstSHA256	1
#define dgstSHA512	2

int init()
{
  EVP_add_cipher(EVP_des_ede3_cbc());
  EVP_add_digest(EVP_sha1());
  EVP_add_digest(EVP_sha256());
  EVP_add_digest(EVP_sha512());
//  ERR_load_crypto_strings();
  return(0);
}

int deallocCA(char *output[])
{
  if(*output!=NULL)
  {
	free(*output);
	*output=NULL;
	return(1);
  }
  return(0);
}

int Decrypt(char *output[],char certsigfile[],char privsigfile[],char data[],int **datasize)
{
  BIO *temp;
  PKCS7 *pke=NULL;
  X509 *x509=NULL;
  EVP_PKEY *pkey=NULL;

  FILE *fp;
  char radka[1000];
  int i=0,j=0,pos=0;

// Private key read

  fp = fopen(privsigfile, "r");
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s privátním klíèem
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey); //ERR:Chyba pøi parsování PEM kódovaného privátního klíèe ze souboru s privátním klíèem

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s certifikátem (veøejným klíèem)
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509); //ERR:Chyba pøi parsování PEM kódovaného certifikátu ze souboru s certifikátem (veøejný klíè)

// preparing PKCS7 envelope
/*
  pke = PKCS7_new();
  PKCS7_set_type(pke, NID_pkcs7_enveloped);
  ERR_print_errors_fp (stderr);
  PKCS7_set_cipher(pke, EVP_des_ede3_cbc()); //must be added
  ERR_print_errors_fp(stderr);
  PKCS7_add_recipient(pke, x509);
*/
// data copying to PKCS7 structure
  temp=BIO_new(BIO_s_mem());
  BIO_write(temp,data,*(*datasize));
  pke=PEM_read_bio_PKCS7(temp,NULL,NULL,NULL);
  BIO_free_all(temp);  
  CHECK(pke); //ERR:Chyba pøi parsování vstupní PKCS7 struktury (nevalidní?)

// get data

  temp = PKCS7_dataDecode(pke, pkey, NULL, x509);
//  ERR_print_errors_fp (stderr);
//  BIO_flush(temp);

// get data from pkcs7
//  i2d_PKCS7_bio(temp,pke); //writing PKCS7 data to memory stream
  CHECK(temp); //ERR:Chyba pøi dekódování dat

  *(*datasize)=(BIO_ctrl_pending(temp))/sizeof(char); //sizeof(char) == 1 in most cases, but who knows...
  if(*output!=NULL) free(*output);
  *output=(char*)malloc(sizeof(char)*(*(*datasize))); //data output 
  
  while((j=BIO_read(temp,radka,1000))>0) //while it can be read
  {
	for(i=0;i<j;i++) //copy byte by byte (char by char :-)
	{
	  (*output)[i+pos]=radka[i]; //aka output[0][i+pos]=radka[i];
	}
	pos+=j;
  }

  *(*datasize)=pos; //why? ctrl_pending not reliable?

// no memory leaks
  BIO_free_all(temp);
  EVP_PKEY_free(pkey);
  PKCS7_free(pke);
  X509_free(x509);

// return something clever
  return(0);
}

int Encrypt(char *output[],char cert[],char data[],int datasize)
{
  BIO *temp,*p7bio=NULL;
  PKCS7 *pke=NULL;
  X509 *x509=NULL;
  int delka,pos=0,i=0,j=0;
  char radka[1000];

// public cert read from string using memory BIO

  temp=BIO_new(BIO_s_mem());
  BIO_write(temp,cert,strlen(cert)); //strlen <--> base64 encoded
  x509=PEM_read_bio_X509(temp,NULL,NULL,NULL);
  BIO_free_all(temp);
  CHECK(x509); //ERR:Chyba pøi parsování PEM kódovaného certifikátu ze vstupu (veøejný klíè)

// preparing PKCS7 envelope

  pke = PKCS7_new();
  CHECK(pke); //ERR:Chyba pøi vytváøení PKCS7 struktury (interní chyba)
  PKCS7_set_type(pke, NID_pkcs7_enveloped);
  PKCS7_set_cipher(pke, EVP_des_ede3_cbc()); //must be added
  PKCS7_add_recipient(pke, x509);

// data copying to PKCS7 structure
  p7bio = PKCS7_dataInit(pke, NULL);
  CHECK(p7bio); //ERR:Chyba pøi získání BIO pro zápis dat do PKCS7 struktury (interní chyba)
  BIO_write(p7bio,data,datasize);
  BIO_flush(p7bio);
  PKCS7_dataFinal(pke,p7bio);
  BIO_free_all(p7bio);

// PKCS7 ready, writing PKCS7-PEM

  temp=BIO_new(BIO_s_mem());
  CHECK(temp); //ERR:Chyba pøi vytváøení memory BIO streamu (interní chyba)
  PEM_write_bio_PKCS7(temp,pke); //writing PKCS7 to memory stream with PEM enconding
  delka=(BIO_ctrl_pending(temp))/sizeof(char)+1; //sizeof(char) == 1 in most cases, but who knows... + 1 for '\0'
  if(*output!=NULL) free(*output);
  *output=(char*)malloc(sizeof(char)*delka); //data output 
  
  while((j=BIO_read(temp,radka,1000))>0) //while it can be read
  {
	for(i=0;i<j;i++) //copy byte by byte (char by char :-)
	{
	  (*output)[i+pos]=radka[i]; //aka output[0][i+pos]=radka[i];
	}
	pos+=j;
  }
  (*output)[delka-1]='\0'; //end of string; output[0][delka-1]='\0';

// no memory leaks
  BIO_free_all(temp);
  PKCS7_free(pke);
  X509_free(x509);

//return something clever :-)
  return(0);
}

int SignEncrypt(char *output[],char certencfile[],char certsigfile[], char privsigfile[],char data[],int datasize,int digest)
{
  FILE *fp;
  PKCS7 *pk=NULL;
  PKCS7_SIGNER_INFO *si;
  X509 *x509=NULL;
  EVP_PKEY *pkey=NULL;
  BIO *pkBIO,*temp;
  int delka,pos=0,i=0,j=0;
  char radka[1000],*sigoutput;
  
// Private key read

  fp = fopen(privsigfile, "r");
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s privátním klíèem
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey); //ERR:Chyba pøi parsování PEM kódovaného privátního klíèe ze souboru s privátním klíèem

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s certifikátem (veøejným klíèem)
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509); //ERR:Chyba pøi parsování PEM kódovaného certifikátu ze souboru s certifikátem (veøejný klíè)

// preparing PKCS7 strucure
  pk=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_signed);
  CHECK(pk); //ERR:Chyba pøi vytváøení PKCS7 struktury (interní chyba)

// add signature
  switch(digest)
  {
    case dgstSHA256:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha256());break;
	case dgstSHA512:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha512());break;
	default:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha1());
  }
  CHECK(si); //ERR:Problém s pøidáním signatury do PKCS7 struktury (interní chyba)

// add current time
  PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,OBJ_nid2obj(NID_pkcs7_data));

// add certificate for check
  PKCS7_add_certificate(pk,x509);

// add content for signing
  PKCS7_content_new(pk,NID_pkcs7_data);
  pkBIO=PKCS7_dataInit(pk,NULL);
  CHECK(pkBIO); //ERR:Chyba pøi získání BIO streamu pro PKCS7 obálku (interní chyba)
  BIO_write(pkBIO,data,datasize);
  BIO_flush(pkBIO);
  PKCS7_dataFinal(pk,pkBIO);
  BIO_free_all(pkBIO);

// write PKCS7 to memory stream, DER encoded (!)

  temp=BIO_new(BIO_s_mem());
  CHECK(temp); //ERR:Chyba pøi vytváøení memory BIO streamu (interní chyba)
  i2d_PKCS7_bio(temp, pk);; //writing PKCS7 to memory stream with DER enconding
  delka=(BIO_ctrl_pending(temp)); //number of bytes (char)
  sigoutput=(char*)malloc(sizeof(char)*delka); //data output 
  
  while((j=BIO_read(temp,radka,1000))>0) //while it can be read
  {
	for(i=0;i<j;i++) //copy byte by byte (char by char :-)
	{
	  sigoutput[i+pos]=radka[i];
	}
	pos+=j;
  }

// no memory leaks
  EVP_PKEY_free(pkey);
  BIO_free_all(temp);
  PKCS7_free(pk);
  X509_free(x509);

//  PKCS7_signer_info_free();
    
// Envelope it!
  Encrypt(output,certencfile,sigoutput,delka);

// free garbage
  free(sigoutput); //not needed now

// return
  return(0);
}

int digestSHA1(char *output[],unsigned char input[],int size)
{
  int i;
  unsigned char dgst[SHA_DIGEST_LENGTH];
  unsigned char *ret;
	
  ret=SHA1(input,size,dgst);

  CHECK(ret); //ERR:Chyba pøi vytváøení binary digest

  if(*output!=NULL) free(*output);
  *output=(char*)malloc(SHA_DIGEST_LENGTH*2+1);

  for (i=0; i<SHA_DIGEST_LENGTH; i++) //konverze binary do HEX string
  {		
	  sprintf(&((*output)[i*2]),"%02x",(unsigned char)dgst[i]);
  }
  (*output)[SHA_DIGEST_LENGTH*2]='\0';

  return(0);
}

int searchTag(char *output[], char input[], char tag[], char value[])
{
  int i;
  char *p1=NULL,*p2=NULL,*p3=NULL,*p4=NULL,*p5=NULL,*p6=NULL;

  p1=(char*)strstr(input,tag); // najdi tag (napø. ViewState)
  CHECK(p1); //ERR:Nenalezen tag v searchTag

  //hledej value od tag dále
  p2=(char*)strstr(p1,value);

  if(p2==NULL) //value nenalezena
  {
    p2=(char*)strstr(input,value);//hledej od zaèátku
	CHECK(p2); //ERR:Nenalezen value v searchTag (dopøednì i zpìtnì)
	p5=p2+sizeof(char); //hledáme až za první value
	p6=p5; //pro hledací skoro-algoritmus :-)
	while(p5!=NULL) //chceme se dostat až na poslední výskyt pøed tag
	{
      p5=(char*)strstr(p6,value); //najdi další výskyt
	  if((p5>=p1)||(p5==NULL)) {break;} //pokud jsme na nebo za tag nebo další výskyt už není, pak nechceme dál
	  else  //jinak iterace
	  {
		p2=p5;
		p6=p5+sizeof(char);
	  };
	}
  }

  p3=(char*)strstr(p2,"\""); // najdi první závorky
  CHECK(p3); //ERR:Nalezena hodnota value, nenalezeny otevírací \"
  p3+=sizeof(char); //za závorku
//  p4=(char*)strstr(p3[1],"\""); //najdi ukonèující závorky ??? proè to nejde
  p4=(char*)strstr(p3,"\"");
  CHECK(p4); //ERR:Nalezena hodnota value, nenalezeny zavírací \"
  if(*output!=NULL) free(*output);
  i=(int)(p4-p3);
  (*output)=(char*)malloc(i+1); //zakonèovací NULL
  CHECK(*output); //ERR:Problém s alokací pamìti (interní)
  strncpy(*output,p3,i);
  (*output)[i]='\0'; //zakonèovací NULL
  return(0);
}

int Sign(char *output[],char certsigfile[], char privsigfile[],char data[],int datasize,int digest)
{
  FILE *fp;
  PKCS7 *pk=NULL;
  PKCS7_SIGNER_INFO *si;
  X509 *x509=NULL;
  EVP_PKEY *pkey=NULL;
  BIO *pkBIO,*temp;
  int delka,pos=0,i=0,j=0;
  char radka[1000];
  
// Private key read

  fp = fopen(privsigfile, "r");
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s privátním klíèem
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey); //ERR:Chyba pøi parsování PEM kódovaného privátního klíèe ze souboru s privátním klíèem

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp); //ERR:Chyba pøi otevírání souboru s certifikátem (veøejným klíèem)
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509); //ERR:Chyba pøi parsování PEM kódovaného certifikátu ze souboru s certifikátem (veøejný klíè)

// preparing PKCS7 strucure
  pk=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_signed);
  CHECK(pk); //ERR:Chyba pøi vytváøení PKCS7 struktury (interní chyba)

// add signature
  switch(digest)
  {
    case dgstSHA256:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha256());break;
	case dgstSHA512:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha512());break;
	default:si=PKCS7_add_signature(pk,x509,pkey,EVP_sha1());
  }
  CHECK(si); //ERR:Problém s pøidáním signatury do PKCS7 struktury (interní chyba)

// add current time
  PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,OBJ_nid2obj(NID_pkcs7_data));

// add certificate for check
  PKCS7_add_certificate(pk,x509);

// add content for signing
  PKCS7_content_new(pk,NID_pkcs7_data);
  pkBIO=PKCS7_dataInit(pk,NULL);
  CHECK(pkBIO); //ERR:Chyba pøi získání BIO streamu pro PKCS7 obálku (interní chyba)
  BIO_write(pkBIO,data,datasize);
  BIO_flush(pkBIO);
  PKCS7_dataFinal(pk,pkBIO);
  BIO_free_all(pkBIO);
/*
// write PKCS7 to memory stream, DER encoded (!)

  temp=BIO_new(BIO_s_mem());
  CHECK(temp); //ERR:Chyba pøi vytváøení memory BIO streamu (interní chyba)
  i2d_PKCS7_bio(temp, pk);; //writing PKCS7 to memory stream with DER enconding
  delka=(BIO_ctrl_pending(temp)); //number of bytes (char)
  sigoutput=(char*)malloc(sizeof(char)*delka); //data output 
  
  while((j=BIO_read(temp,radka,1000))>0) //while it can be read
  {
	for(i=0;i<j;i++) //copy byte by byte (char by char :-)
	{
	  sigoutput[i+pos]=radka[i];
	}
	pos+=j;
  }
*/

  // PKCS7 ready, writing PKCS7-PEM

  temp=BIO_new(BIO_s_mem());
  PEM_write_bio_PKCS7(temp,pk); //writing PKCS7 to memory stream with PEM enconding
  delka=(BIO_ctrl_pending(temp))/sizeof(char)+1; //sizeof(char) == 1 in most cases, but who knows... + 1 for '\0'
  if(*output!=NULL) free(*output);
  *output=(char*)malloc(sizeof(char)*delka); //data output 
  
  while((j=BIO_read(temp,radka,1000))>0) //while it can be read
  {
	for(i=0;i<j;i++) //copy byte by byte (char by char :-)
	{
	  (*output)[i+pos]=radka[i]; //aka output[0][i+pos]=radka[i];
	}
	pos+=j;
  }
  (*output)[delka-1]='\0'; //end of string; output[0][delka-1]='\0';

// no memory leaks
  EVP_PKEY_free(pkey);
  BIO_free_all(temp);
  PKCS7_free(pk);
  X509_free(x509);

//  PKCS7_signer_info_free();
    
// free garbage
//  free(sigoutput); //not needed now

// return
  return(0);
}

//TO-DO --> comments and other things

int URLencode(char *output[],const char original[])
{
    int counter, out_counter;
    char buffer[4]; // buffer to hold hexidecimal version of the character
	
	if(*output!=NULL) free(*output);
	*output = (char *)malloc((strlen(original)*2)+1); // will make sure there is enough room for new string

	CHECK(output);//ERR:Chyba pøi alokování pamìti

	for(counter=0,out_counter=0;counter<(int)strlen(original);counter++,out_counter++)
    {
        if(isalnum(original[counter]))
            (*output)[out_counter]=original[counter];
        else
        {
            if(original[counter]=='\n')
			{
			  (*output)[out_counter++]='%';
			  (*output)[out_counter++]='0';
			  (*output)[out_counter++]='D';
			  (*output)[out_counter++]='%';
			  (*output)[out_counter++]='0';
			  (*output)[out_counter]='A';
			}
			else
			{
		      sprintf(buffer, "%%%X", original[counter]); //prints %Hex_Value (%20) of the original character
              //grabs first three characters of the buffer which is the hex value we want
              (*output)[out_counter++] = buffer[0];
              (*output)[out_counter++] = buffer[1];
              (*output)[out_counter] = buffer[2];
			}
        }

    }
    (*output)[out_counter]='\0'; //end the string
  return(0);
}

int findStr(char *output[],const char input[], const char lb[],const char rb[])
{
  char *p1=NULL,*p2=NULL;

  p1=(char*)strstr(input,lb); // najdi tag (napø. ViewState)
  CHECK(p1); //ERR:Nenalezen LB v input
  p1+=strlen(lb);
  
  p2=(char*)strstr(p1,rb);
  CHECK(p2); //ERR:Nenalezen RB v input

  printf("Vystup %i",p2-p1+1);

  if(*output!=NULL) free(*output);
  (*output)=(char*)malloc(p2-p1+1); //alokování pro výstup
  CHECK(*output); //ERR:Chyba v alokování pamìti pro výstup

  strncpy(*output,p1,p2-p1);
  (*output)[p2-p1]='\0';

  return(0);
}
