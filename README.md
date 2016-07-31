# CryptLib
Crypto library helper for LoadRunner (experimental)

_Usage_ 
1. Grab a dll (DecEncDLL.dll) and put in a file system
2. Install MC VC++ runtime (9.0 at least)
3. Link your Load runner script to the dll

_Notice_
* cert should be PEM encoded


```c

#define DEBUG //DEBUG output on
#define MAXPARAM "50000" //max lenght of parsed param
#define CHECK(p) if(!(p)) {\
  lr_error_message("Check (%s) failed -- file %s line %d\n",#p,__FILE__,__LINE__);\
  lr_set_transaction_status(LR_STOP);\
  goto konec;}
#define RET(p) if((nret=(p))!=0) {\
  lr_error_message("Check for function (%s) failed -- return code %d",#p,nret);\
  goto konec;}
#define FREE(p) free((p));\
  (p)=NULL;
#define INITTT	#ifndef DEBUG\
  lr_think_time(3);\
  #endif
#define BEFTT	#ifndef DEBUG\
  lr_think_time(4);\
  #endif


#define BTRAN(x)  tran=(x);\
  lr_start_transaction((x));
#define ETRAN  lr_end_transaction(tran,LR_AUTO);\
  tran=NULL;



Action()
{
  char *output=NULL,*action=NULL,*viewState=NULL; //for crypto in/out
  int *size=NULL,i;
  char hash[128],nonce[128];
  char *buffer=NULL,pom[256],pom2[256],*pom3=NULL,exec[256];
  int nret=0;
  char *tran=NULL;
  int HttpRetCode;

#ifdef DEBUG
  ci_set_debug(ci_this_context, 1, 1); /* turn ON trace & debug */
#endif

  
  size=(int*)malloc(sizeof(int));

  lr_load_dll(lr_eval_string("c:\\DecEncDLL.dll"));

  web_set_max_html_param_len(MAXPARAM); //because of the long param lenght
  ...



//digestSHA1(char *output[],char input[],int size) -- double SHA1

  buffer=(char*)malloc(128); // buffer allocation

  strcpy(buffer,"login"); //login
  strcat(buffer,"password"); //password

#ifdef DEBUG
  lr_output_message("Buffer: %s\n",buffer); 
#endif

  RET(digestSHA1(&output,buffer,strlen(buffer))); //check the return

#ifdef DEBUG
  lr_output_message("HASH1: %s\n",output); //first hash
#endif

  strcpy(buffer,output);
  strcat(buffer,lr_eval_string("{nonce}"));

  RET(digestSHA1(&output,buffer,strlen(buffer)));

#ifdef DEBUG
  lr_output_message("HASH2: %s\n",output); 
#endif

  strcpy(buffer,"Value=");
  strcat(buffer,output);

  deallocCA(&output); //do not forget to deallocate the memory that has been allocated by dll

#ifdef DEBUG
  lr_output_message("Buffer: %s\n",buffer); 
#endif