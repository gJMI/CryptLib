#include <stdio.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <sys\stat.h>
#include <crtdbg.h>
#include <time.h>

#define DBGMALLOC(x) _malloc_dbg((x),_NORMAL_BLOCK,__FILE__, __LINE__)
#define DBGFREE(x) _free_dbg((x),_NORMAL_BLOCK)

#define _CRTDBG_MAP_ALLOC 
#define lr_message printf

#define CHECK(x) if((x)==NULL) return(__LINE__);
#define dgstSHA1	0
#define dgstSHA256	1
#define dgstSHA512	2

#define MALLOCSTR(x,y) {\
  (x)=(char*)malloc((y));\
  }

int init();
int Encrypt(char *output[],char cert[],char data[],int datasize);
int SignEncrypt(char *output[],char certencfile[],char certsigfile[], char privsigfile[],char data[],int datasize);
int Decrypt(char *output[],char certsigfile[],char privsigfile[],char data[],long int **datasize);
int deallocCA(char *output[]);
int digestSHA1(char *output[],unsigned char input[],int size);
int searchTag(char *output[], char input[], char tag[], char value[]);
int Sign(char *output[],char certsigfile[], char privsigfile[],char data[],int datasize);
int URLencode(char *output[],const char original[]);
int findStr(char *output[],const char input[], const char lb[],const char rb[]);

int main(int argc,char** argv)
{
  static char keyfile[]  = "c:\\temp\\radislav.key"; //"c:\\temp\\radislav .key";
  static char certfile[] = "c:\\temp\\radislav.pem"; //"C:\\temp\\radislav .cer";
  static char inputfile[] = "c:\\temp\\JPU_yellow_in.p7m"; //"c:\\temp\\JPU_yellow_in.p7m";
  static char outputfileenc[] = "c:\\temp\\JPU_yellow2.p7m";
  static char outputfiledec[] = "c:\\temp\\decrypted.p7m";
  static char servercertfile[] = "-----BEGIN CERTIFICATE-----\nMIIDYjCCA+mYFniKC2px9miinuLyyvIg07seDiVY/aI\n4pRo1xHQKdYNimJtmMZRxH8d4jvjpSMAiqzqhW7B0qPKrHskIvOs0CjrX2hxtdFuxjqJMiO/YoJ7\nCUXffhgDQnlhLP0uPCsi\n-----END CERTIFICATE-----";
  char encodedfile[]="";
  static char datatoencode[]="formattedaccount=0&userpayees=&recaccountprefix=&recaccountnumber=123&recbankcode=800&amount=123&recipientvariablesymbol=&constantsymbol=&recspecificsymbol=&accountingdate=22%2F07%2F2010&messageforrecipient=&j_id303=Cross+field+component+fake+value&org.apache.myfaces.trinidad.faces.FORM=form_debPoCreate_trn&_noJavaScript=false&javax.faces.ViewState=%213&source=doNext";
  char *output=NULL,*data;
  char *buffer=NULL;
  FILE *f;
  long int *size=NULL;//(int*)DBGMALLOC(sizeof(int));
  //int size;
  struct stat status;
  int i,j,k,x=0;
  char hello[]="2222222222PASSSSS";
  char hello2[]="Hello world...";

 
  char hello3[]="Hello\nWorld\n";

  MALLOCSTR(buffer,(strlen("{response}")+(54+10)));
  
  trimEnd(&hello3);



//  findStr(&output,"Hello world<div>ahoj jak se m��</div>", "<div>","</div>");
  
//  printf("Hello world %s",output);
  
  init();

  buffer=(char*)malloc(100000);

  strcpy(buffer,"<!--Start: org.apache.myfaces.trinidad.Form[\"j_id282\"]--><span id=\"tr_toppane_form_Postscript\"><input type=\"hidden\" name=\"javax.faces.ViewState\" value=\"!4\"><input type=\"hidden\" name=\"source\"><script type=\"text/javascript\">TrPage.getInstance()._addResetFields('toppane_form',[\"source\"]);</script><script type=\"text/javascript\">function _toppane_formValidator(f,s){return _validateInline(f,s);}var toppane_form_SF={};</script></span><script type=\"text/javascript\">_submitFormCheck();</script></form>\n        \n<div class=\"navBar\" style=\"clear:both;\">\n    <div id=\"navBarText\" class=\"navbar_tab_cli\"><!--Start: org.apache.myfaces.trinidad.Output[\"j_id77\"]-->P&#345;ehled klient&#367; a jejich &uacute;&#269;t&#367;, v&yacute;b&#283;r klienta</div>\n</div>\n<script type=\"text/javascript\">\n");
  findStr(&output,buffer,"<span id=\"tr_toppane_form_Postscript\"","</span>");

  
  
 

  ERR_load_crypto_strings();


//  URLencode(&output,datatoencode);

//  printf("Vystup: %s\n",output);

  //URLencode(&output,encodedfile);

  //printf("Vystup: %s\n",output);

  size=(int*)DBGMALLOC(sizeof(int));
  *size=strlen(buffer);
  //*size=10000;

  Decrypt(&output,certfile,keyfile,buffer,&size);

  output[(*size)]='\0';

  ERR_print_errors_fp(stderr);

  printf("Size %i\n",size);
  printf("Output \n%s\n",output);

  if(argc!=3)
  {
	printf("Pouziti: %s inputfile outputfile",argv[0]);
	printf("\n\ninputfile -- text file k zakodovani\noutputfile -- pkcs7-envelopedData PEM zasifrovany\n");
	return(15);
  }
  
  f=fopen(argv[1],"r");
  if(f==NULL) 
  {
	printf("Chyba v otevreni %s souboru pro cteni",argv[1]);
	return(2);
  }
  
  fstat(fileno(f),&status); //lenght of file (?)
  //printf("Size of file is %d\n",status.st_size);
  data=(char*)DBGMALLOC(sizeof(char)*status.st_size);
  size=(int*)DBGMALLOC(sizeof(int));  
  *size=fread(data,sizeof(char),status.st_size,f);
  fclose(f);

//  Encrypt(&output,servercertfile,data,*size);
  Sign(&output,"c:\\temp\\radislav.pem","c:\\temp\\radislav.key",data,*size);

  f=fopen(argv[2],"w");
  if(f==NULL) 
  {
	printf("Chyba v otevreni %s souboru pro zapis",argv[2]);
	return(2);
  }
  
  fwrite(output,sizeof(char),strlen(output),f);
  fclose(f);

  DBGFREE(data);
  DBGFREE(size);

  _CrtDumpMemoryLeaks(); 

  /*
  *size=strlen(hello2);
  output=(char*)DBGMALLOC(sizeof(char));
  strcpy(output,"ahoj");
  for(j=0,k=0;j<strlen(servercertfile);j++,k++)
  {
    char a=servercertfile[j];
	strcat(output,"this");
	//strncat(output,servercertfile[j],sizeof(char));
	if(k>80)
	{
	  strcat(output,"\n");
      k=0;
	}
  }
  
  */
  //Encrypt(&output,servercertfile,hello2,*size);

}

int init()
{
  EVP_add_cipher(EVP_des_ede3_cbc());
  EVP_add_digest(EVP_sha1());
  EVP_add_digest(EVP_sha256());
  EVP_add_digest(EVP_sha512());
  ERR_load_crypto_strings();
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

int Decrypt(char *output[],char certsigfile[],char privsigfile[],char data[],long int **datasize)
{
  BIO *temp;
  PKCS7 *pke=NULL;
  X509 *x509=NULL;
  EVP_PKEY *pkey=NULL;

  FILE *fp;
  char radka[40000];
  int i=0,j=0,pos=0;

// Private key read

  fp = fopen(privsigfile, "r");
  CHECK(fp);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey);

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp);
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509);

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
  CHECK(pke);

// get data

  temp = PKCS7_dataDecode(pke, pkey, NULL, x509);
//  ERR_print_errors_fp (stderr);
//  BIO_flush(temp);

// get data from pkcs7
//  i2d_PKCS7_bio(temp,pke); //writing PKCS7 data to memory stream
  *(*datasize)=(BIO_ctrl_pending(temp))/sizeof(char); //sizeof(char) == 1 in most cases, but who knows...
  if(*output!=NULL) free(*output);
  *output=(char*)malloc(sizeof(char)*(*(*datasize))); //data output 
  
  while((j=BIO_read(temp,radka,40000))>0) //while it can be read
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
  CHECK(x509);

// preparing PKCS7 envelope

  pke = PKCS7_new();
  CHECK(pke);
  PKCS7_set_type(pke, NID_pkcs7_enveloped);
  PKCS7_set_cipher(pke, EVP_des_ede3_cbc()); //must be added
  PKCS7_add_recipient(pke, x509);

// data copying to PKCS7 structure
  p7bio = PKCS7_dataInit(pke, NULL);
  CHECK(p7bio);
  BIO_write(p7bio,data,datasize);
  BIO_flush(p7bio);
  PKCS7_dataFinal(pke,p7bio);
  BIO_free_all(p7bio);

// PKCS7 ready, writing PKCS7-PEM

  temp=BIO_new(BIO_s_mem());
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

int SignEncrypt(char *output[],char certencfile[],char certsigfile[], char privsigfile[],char data[],int datasize)
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
  CHECK(fp);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey);

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp);
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509);

// preparing PKCS7 strucure
  pk=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_signed);
  CHECK(pk);

// add signature
//  si=PKCS7_add_signature(pk,x509,pkey,EVP_sha1());
  si=PKCS7_add_signature(pk,x509,pkey,EVP_sha256());


// add current time
  PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,OBJ_nid2obj(NID_pkcs7_data));

// add certificate for check
  PKCS7_add_certificate(pk,x509);

// add content for signing
  PKCS7_content_new(pk,NID_pkcs7_data);
  pkBIO=PKCS7_dataInit(pk,NULL);
  BIO_write(pkBIO,data,datasize);
  BIO_flush(pkBIO);
  PKCS7_dataFinal(pk,pkBIO);
  BIO_free_all(pkBIO);

// write PKCS7 to memory stream, DER encoded (!)

  temp=BIO_new(BIO_s_mem());
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

int Sign(char *output[],char certsigfile[], char privsigfile[],char data[],int datasize)
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
  CHECK(fp);
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  CHECK(pkey);

// Public cert for private key read
  fp = fopen (certsigfile, "r"); // for DER it has to be "rb"
  CHECK(fp);
  x509 = PEM_read_X509(fp, NULL, NULL, NULL); //PEM
//  x509 = d2i_X509_fp(fp,NULL); //DER
  fclose (fp);
  CHECK(x509);

// preparing PKCS7 strucure
  pk=PKCS7_new();
  PKCS7_set_type(pk,NID_pkcs7_signed);
  CHECK(pk);

// add signature
//  si=PKCS7_add_signature(pk,x509,pkey,EVP_sha1());
  si=PKCS7_add_signature(pk,x509,pkey,EVP_sha256());


// add current time
  PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,OBJ_nid2obj(NID_pkcs7_data));

// add certificate for check
  PKCS7_add_certificate(pk,x509);

// add content for signing
  PKCS7_content_new(pk,NID_pkcs7_data);
  pkBIO=PKCS7_dataInit(pk,NULL);
  BIO_write(pkBIO,data,datasize);
  BIO_flush(pkBIO);
  PKCS7_dataFinal(pk,pkBIO);
  BIO_free_all(pkBIO);

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

int URLencode(char *output[],const char original[])
{
    int counter, out_counter;
    char buffer[4]; // buffer to hold hexidecimal version of the character
	
	if(*output!=NULL) free(*output);
	*output = (char *)malloc((strlen(original)*2)+1); // will make sure there is enough room for new string

	printf("strlen %i\n",strlen(original));

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


genABO(char ucet[],char out[],int size)
{
  int i,day,month,year;
  char temp[20];
  //typedef long time_t;
  struct tm { 
       int tm_sec; /* seconds after the minute - [0,59] */ 
       int tm_min; /* minutes after the hour - [0,59] */ 
       int tm_hour; /* hours since midnight - [0,23] */ 
       int tm_mday; /* day of the month - [1,31] */ 
       int tm_mon; /* months since January - [0,11] */ 
       int tm_year; /* years since 1900 */ 
       int tm_wday; /* days since Sunday - [0,6] */ 
       int tm_yday; /* days since January 1 - [0,365] */ 
       int tm_isdst; /* daylight savings time flag */ 
  }; 

  //time_t t;
  __time64_t t;
  struct tm *now;

  
  //_tzset(); // moved to vuser_init()
  time(&t);
  now = (struct tm *)localtime(&t);
  
  

  day=now->tm_mday+14;
  month=now->tm_mon+1;
  year=now->tm_year-100;

  if(day>29)
  {
    day=1;
	month>11?month=1,year++:month++;
  }

//  free(now);

  strcpy(out,"UHL1290305Drahomira Dvorakova 7325947277001010000000000000\n1 1501 010799 0800\n2 000000-");
  strcat(out,ucet);
  strcat(out," ");
//  strcat(out,"00000000000840"); //sou�et ��stky v hal���ch!!! printf("");
  sprintf(temp,"%014i",size*20);
#ifdef DEBUG
  lr_message("Hal���: %s",temp);
#endif
  strcat(out,temp);
  strcat(out," ");
  sprintf(temp,"%02i%02i%02i",day,month,year); //m�s�c dop�edu splatnost
#ifdef DEBUG
  lr_message("Datum splatnosti: %s",temp);
#endif
  strcat(out,temp); //datum splatnosti DDMMRR (aktu�ln� datum + 1 m�s�c)
  strcat(out,"\n");
  for(i=1;i<=size;i++)
  {
	strcat(out,"0000000123 "); //��slo ��tu p��jemce
	strcat(out,"000000000020 "); //��stka v hal���ch
	strcat(out,"0021850103 "); //variablin� symbol
	strcat(out,"0800"); //k�d banky p��jemce 
	strcat(out,"0308 "); //konst symbol
	strcat(out,"0000000123 "); //variabilni symbol
	strcat(out,"Prikaz"); //zprava pro p��jemce
    itoa(i,temp,10);
	strcat(out,temp);
	strcat(out,"\n");
  }
  strcat(out,"3 +\n5 +");
}

int digestSHA1(char *output[],unsigned char input[],int size)
{
  int i;
  unsigned char dgst[SHA_DIGEST_LENGTH];
  unsigned char *ret;
	
  ret=SHA1(input,size,dgst);

  CHECK(ret); //ERR: Chyba p�i vytv��en� binary digest

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

  p1=(char*)strstr(input,tag); // najdi tag (nap�. ViewState)
  CHECK(p1); //ERR: Nenalezen tag v searchTag

  //hledej value od tag d�le
  p2=(char*)strstr(p1,value);

  if(p2==NULL) //value nenalezena
  {
    p2=(char*)strstr(input,value);//hledej od za��tku
	CHECK(p2); //ERR: Nenalezen tag v searchTag (dop�edn� i zp�tn�)
	p5=p2+sizeof(char); //hled�me a� za prvn� value
	p6=p5; //pro hledac� skoro-algoritmus :-)
	while(p5!=NULL) //chceme se dostat a� na posledn� v�skyt p�ed tag
	{
      p5=(char*)strstr(p6,value); //najdi dal�� v�skyt
	  if((p5>=p1)||(p5==NULL)) {break;} //pokud jsme na nebo za tag nebo dal�� v�skyt u� nen�, pak nechceme d�l
	  else  //jinak iterace
	  {
		p2=p5;
		p6=p5+sizeof(char);
	  };
	}
  }

  p3=(char*)strstr(p2,"\""); // najdi prvn� z�vorky
  CHECK(p3); //ERR: Nalezena hodnota value, nenalezeny otev�rac� \"
  p3+=sizeof(char); //za z�vorku
//  p4=(char*)strstr(p3[1],"\""); //najdi ukon�uj�c� z�vorky ??? pro� to nejde
  p4=(char*)strstr(p3,"\"");
  CHECK(p4); //ERR: Nalezena hodnota value, nenalezeny zav�rac� \"
  if(*output!=NULL) free(*output);
  i=(int)(p4-p3);
  (*output)=(char*)malloc(i+1); //zakon�ovac� NULL
  CHECK(*output); //ERR: Probl�m s alokac� pam�ti (intern�)
  strncpy(*output,p3,i);
  (*output)[i]='\0'; //zakon�ovac� NULL
  return(0);
}

int findStr(char *output[],const char input[], const char lb[],const char rb[])
{
  char *p1=NULL,*p2=NULL;

  p1=(char*)strstr(input,lb); // najdi tag (nap�. ViewState)
  CHECK(p1); //ERR: Nenalezen LB v input
  p1+=strlen(lb);

  p2=(char*)strstr(p1,rb);
  CHECK(p2); //ERR: Nenalezen RB v input

  printf("Vystup %i",p2-p1+1);

  if(*output!=NULL) free(*output);
  (*output)=(char*)malloc(p2-p1+1); //alokov�n� pro v�stup
  CHECK(*output); //ERR: Chyba v alokov�n� pam�ti pro v�stup

  strncpy(*output,p1,p2-p1);
  (*output)[p2-p1]='\0';

  return(0);
}

int trimEnd(char input[])
{
  int i;

  i=strlen(input); 
  if((char)(input[i-1])=='\n')
    input[i-1]='\0';
  return(0); 
}