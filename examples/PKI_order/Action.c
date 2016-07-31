/* PKI nIB B24 zadani JPU -- s aplika�n�ho/plugin �ifrov�n�
*  datum splatnosti dopredne
*
*  JMI 2010
*
*  verze: 0.81
*
*/

#include "as_web.h"
#include "prostredi.h"

#define SHA1	0 // defaultn�
#define SHA256	1
#define SHA512	2
#define _SHA	SHA512 //nastaven� SHA

#define DEBUG //zobrazen� DEBUG v�stup�
#define MAXPARAM "300000" //maxim�ln� d�lka parsovan�ho parametru
#define CHECK(p) if(!(p)) {\
  lr_error_message("Check (%s) failed -- file %s line %d\n",#p,__FILE__,__LINE__);\
  lr_set_transaction_status(LR_STOP);\
  goto konec;}
#define RET(p) if((nret=(p))!=0) {\
  lr_error_message("Check for function (%s) failed -- return code %d",#p,nret);\
  goto konec;}
#define MALLOCSTR(x,y) {\
  if((x)) lr_error_message("Check variable (%s) allocation on line (%d) for possible memory leak\n",#x,__LINE__);\
  (x)=(char*)malloc((y));\
  }
#define FREE(p) free((p));\
  (p)=NULL;

#define BTRAN(x)  tran=(x);\
  lr_start_transaction((x));
#define ETRAN  lr_end_transaction(tran,LR_AUTO);\
  tran=NULL;


genADate(char den[]);
get_param(const char param[],const char input[], const char lb[],const char rb[]);
int trimEnd(char input[]);

Action()
{
  char *output=NULL,*action=NULL,*viewState=NULL,*nonce=NULL; //p�ed�v�n� crypt/decrypt v�stup�
  int *size=NULL,i;
  char challenge1[70],*p=NULL,hash[50];
  char *buffer=NULL,*buffer2=NULL,pom[256],pom2[256],*pom3=NULL,*pom4=NULL,exec[256];
  char formatedaccount[500],fm[500];
  char *pki_content=NULL;
  char *csas=NULL,*csascert=NULL;
  char adate[20];
  int nret=0,j,k;
  char *tran=NULL;

#ifdef DEBUG
//  ci_set_debug(ci_this_context, 1, 1); /* turn ON trace & debug */
#endif

   size=(int*)malloc(sizeof(int));

  lr_load_dll(DLL_LOCATION);

  web_set_max_html_param_len(MAXPARAM); //nutn� pro sebran� parametry (databody ~ d�vka ABO)
  web_add_cookie("lang=cs; DOMAIN=localhost");
  web_add_cookie("JSESSIONID=; DOMAIN=localhost");


INITTT;
BTRAN("B24_JPU_Login");

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,"/ebanking-b24/ib/base/usr/aut/login");
  web_url("Login Page",pom,LAST); 

  web_reg_save_param("execSPAN","LB=<span id=\"tr_loginForm_Postscript\">","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"loginForm\"","RB=>",LAST);
  web_reg_save_param("execNonce","LB=id=\"id_digest_nonce\"","RB=>",LAST);
  web_reg_save_param("execCert","LB=id=\"id_pkicert\"","RB=>",LAST);

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,"/ebanking-b24/ib/base/usr/aut/login_pki");
  addDynaTraceHeader("NA=;PC=LoginPage");
  web_url("Login Page",pom,LAST); 

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"loginForm","action"));
  RET(searchTag(&nonce,lr_eval_string("{execNonce}"),"id_digest_nonce","value"));
  RET(searchTag(&csascert,lr_eval_string("{execCert}"),"id_pkicert","value")); //? Convert (?)

#ifdef DEBUG
  lr_output_message("nonce: %s\n",nonce);
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
  lr_output_message("csascert: %s\n",csascert);
#endif

  strcpy(challenge1,lr_eval_string("{ClientCardN}"));
  strcat(challenge1,"|");
  strcat(challenge1,nonce);

#ifdef DEBUG
  lr_output_message("Challenge1 %s",challenge1);
#endif

// Encrypt challenge
  //prepare server cert for PKCS7 envelope
  
CHECK(strlen(csascert)>100);

  csas=(char*)malloc(strlen(csascert)+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)
  strcpy(csas,"-----BEGIN CERTIFICATE-----\n");
/*
  for(j=0,k=0;j<strlen(csascert);j++,k++)
  {
    strncat(csas,csascert[j],1);
	if(k>80)
	{
	  strcat(csas,"\n");
      k=0;
	}
  }
*/
  strcat(csas,csascert); //viz smy�ka
  strcat(csas,"\n-----END CERTIFICATE-----");

#ifdef DEBUG
  lr_output_message("Cert size=%i",strlen(csascert));
  lr_output_message("Cert cont=%s",csascert);
  lr_output_message("Cert PKCS7=%s",csas);
  lr_output_message("Cert csas=%p",csas);
  lr_output_message("Size var=%d",size);
#endif

  CHECK(strlen(challenge1)>10);

  RET(Encrypt(&output,csas,challenge1,strlen(challenge1)));

//find first \n
  p = (char*)strstr(output,"\n");
  i = (int)(p-output);

  MALLOCSTR(buffer,strlen(output)+10);//  MALLOCSTR(buffer,strlen(output)+10); // pro Value=
  
  strcpy(buffer,"Value=");
  strcat(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

  p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
  *p='\0';

#ifdef DEBUG
  lr_output_message("Vysledek %s",buffer); 
#endif

// First challenge (AJAX challenge)

  web_reg_save_param("response","LB=<RESPONSE>","RB=</RESPONSE>",LAST);

  strcpy(pom,"Action=");
  strcat(pom,SERVERURL);
  strcat(pom,"/ebanking-b24/loginpki");

  addDynaTraceHeader("NA=;PC=Challenge1");
  web_submit_data("Challenge1",
       pom, 
       "Method=POST",
       ITEMDATA, 
              "Name=cardnumber", buffer,ENDITEM,
              "Name=fakesubmit","Value=ib_trn_login_cardnumber",ENDITEM,
			  "Name=cffvhidformid","Value=ajax",ENDITEM,
       LAST);

#ifdef DEBUG
  lr_output_message("Tohle je response %s",lr_eval_string("{response}"));
#endif

  FREE(buffer);

//Decrypt response
  CHECK(strlen(lr_eval_string("{response}"))>1);
  MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

  strcpy(buffer,"-----BEGIN PKCS7-----\n");
  strcat(buffer,lr_eval_string("{response}"));
  strcat(buffer,"-----END PKCS7-----");

lr_output_message("Tohle je buffer %s",buffer);

  *size=strlen(buffer);

lr_output_message("Size %i",*size);


  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

  FREE(buffer);

#ifdef DEBUG
  lr_message("Vysledek volani de�ifrovan� text=%s\n",output); 
#endif

  p = (char*)strstr(output,"|");
  i = (int)(p-output);

#ifdef DEBUG
  lr_message("Hledany znak=%d\n",i);
#endif

  strncpy(hash,output,i);

#ifdef DEBUG
  lr_message("Hash=%s\n",hash);
#endif

//Encrypt response
  RET(Encrypt(&output,csas,hash,strlen(hash)));
  
//find first \n
  p = (char*)strstr(output,"\n");
  i = (int)(p-output);

  MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

  strcpy(buffer,"Value=");
  strcat(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

  p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
  *p='\0';

#ifdef DEBUG
  lr_output_message("Vysledek %s",buffer); 
#endif

  strcpy(pom2,"Value=");
  strcat(pom2,nonce);

#ifdef DEBUG
  lr_output_message("Nonce string %s",pom2); 
#endif

  strcpy(pom,"Action=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom3,40);
  strcpy(pom3,"Value=");
  strcat(pom3,viewState);




  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript\">","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"ib_form\"","RB=>",LAST);




  addDynaTraceHeader("NA=;PC=LoginmenuVyberklienta");
  web_submit_data("Login menu Vyber klienta",
       pom, 
       "Method=POST",
       ITEMDATA, 
			  "Name=id_digest_nonce",pom2,ENDITEM,
        "Name=id_pkicert","Value=MIIDYjCCAkqgAwIBAgIDBA6/MA0GCSqGSIb3DQEBBQUAMEgxCzAJBgN+mYFniKC2px9miinuLyyvIg07seDiVY/aI\n4pRo1xHQKdYNimJtmMZRxH8d4jvjpSMAiqzqhW7B0qPKrHskIvOs0CjrX2hxtdFuxjqJMiO/YoJ7\nCUXffhgDQnlhLP0uPCsi",ENDITEM, //TO-DO: csascert prom�nn�
			  "Name=id_ajaxUrl","Value=/ebanking-b24/loginpki",ENDITEM,
			  "Name=id_pkicontent", buffer,ENDITEM,
			  "Name=org.apache.myfaces.trinidad.faces.FORM","Value=loginForm",ENDITEM,
			  "Name=_noJavaScript","Value=false",ENDITEM,
			  "Name=javax.faces.ViewState",pom3,ENDITEM,
			  "Name=source","Value=loginBtn",ENDITEM,
       LAST); 

  



ETRAN;

  FREE(buffer);
  FREE(pom3);

//TO-DO

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif

// 5.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom4,15000); //  pom4=(char*)malloc(15000); //buffer pro body

//contracts%3AArangeStart=0&org.apache.myfaces.trinidad.faces.FORM=ib_form&_noJavaScript=false&javax.faces.ViewState=%213&source=contracts%3A2%3AsetContract&state=&value=&contractId=30032668

    strcpy(pom4,"contracts%3AArangeStart=0");
    strcat(pom4,"&org.apache.myfaces.trinidad.faces.FORM=ib_form");
    strcat(pom4,"&_noJavaScript=false");
    strcat(pom4,"&source=contracts%3A2%3AsetContract"); 
    strcat(pom4,"&state=");
    strcat(pom4,"&value=");
    strcat(pom4,"&contractId=30032668");
    strcat(pom4,"&javax.faces.ViewState=");
    strcat(pom4,viewState);

#ifdef DEBUG
  lr_output_message("text to encrypt: %s\n",pom4);
#endif

  RET(Encrypt(&output,csas,pom4,strlen(pom4))); //encrypt body

    //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    //  strcpy(buffer,"Value=");
    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

  FREE(output);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  strcpy(pom4,"Body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 5.2 submit

//  web_add_header ("x-pkcs7-encoded", "True");
  web_add_header("X-Content-Encrypted","NA_PKI1");

// web_reg_save_param("response","LB=<div><![CDATA[","RB=]]></div>",LAST);
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

  addDynaTraceHeader("NA=;PC=LoginMenuVyberklienta");
  web_custom_request("Login Menu Vyber klienta",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

// 5.3 decode response


  //Decrypt response
  CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    strcat(buffer,"-----END PKCS7-----");
    
    *size=strlen(buffer);

#ifdef DEBUG
    lr_output_message("Tohle je buffer %s",buffer);
	lr_output_message("Size %i",*size);
#endif

  //dekryptov�n� vlastn�
  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

#ifdef DEBUG
  lr_output_message("dekryptov�no size %i\n",*size);
#endif

  output[(*size)]='\0'; //zarovn�n� paddingu

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("dekryptov�no %s\n",output);
  lr_output_message("dekryptov�no %i\n",strlen(output));
#endif

  //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execSPAN",output,"<span id=\"tr_toppane_form_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"toppane_form\"",">"));

  //najdi tagy
  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"toppane_form","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif

  FREE(output);


/** 6. krok **/

 //preklik na JPU

// 6.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

//  pom4=(char*)malloc(15000); //buffer pro body
  MALLOCSTR(pom4,15000);

    strcpy(pom4,"&org.apache.myfaces.trinidad.faces.FORM=toppane_form");
    strcat(pom4,"&_noJavaScript=false");
    strcat(pom4,"&source=topMenuTabsLeft%3A2%3AtopMenuItemLink"); 
    strcat(pom4,"&javax.faces.ViewState=");
    strcat(pom4,viewState);

#ifdef DEBUG
  lr_output_message("text to encrypt: %s\n",pom4);
#endif

  RET(Encrypt(&output,csas,pom4,strlen(pom4))); //encrypt body

    //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    //  strcpy(buffer,"Value=");
    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

  FREE(output);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  strcpy(pom4,"Body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 6.2 submit

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

  addDynaTraceHeader("NA=;PC=Platebnistyk");
  web_custom_request("Platebni styk",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

// 6.3 decode response


  //Decrypt response
  CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    strcat(buffer,"-----END PKCS7-----");
    
    *size=strlen(buffer);

#ifdef DEBUG
    lr_output_message("Tohle je buffer %s",buffer);
	lr_output_message("Size %i",*size);
#endif

  //dekryptov�n� vlastn�
  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

#ifdef DEBUG
  lr_output_message("dekryptov�no size %i\n",*size);
#endif

  output[(*size)]='\0'; //zarovn�n� paddingu

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("dekryptov�no %s\n",output);
  lr_output_message("dekryptov�no %i\n",strlen(output));
#endif

  //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execSPAN",output,"<span id=\"tr_toppane_form_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"toppane_form\"",">"));

  //najdi tagy
  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"toppane_form","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif

  FREE(output);


// 7.1 JPU1

// 7.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom4,15000); //pom4=(char*)malloc(15000); //buffer pro body

//contracts%3AArangeStart=0&org.apache.myfaces.trinidad.faces.FORM=ib_form&_noJavaScript=false&javax.faces.ViewState=%213&source=contracts%3A2%3AsetContract&state=&value=&contractId=30032668

    strcpy(pom4,"org.apache.myfaces.trinidad.faces.FORM=menu_form");
    strcat(pom4,"&_noJavaScript=false");
    strcat(pom4,"&source=leftMenu%3A1%3AleftSubmenu%3A0%3AleftSubmenuItem");
    strcat(pom4,"&javax.faces.ViewState=");
    strcat(pom4,viewState);

#ifdef DEBUG
  lr_output_message("text to encrypt: %s\n",pom4);
#endif

  RET(Encrypt(&output,csas,pom4,strlen(pom4))); //encrypt body

    //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    //  strcpy(buffer,"Value=");
    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

  FREE(output);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  strcpy(pom4,"Body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 7.2 submit

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

BTRAN("B24_JPU_Blue_Enc");

  addDynaTraceHeader("NA=;PC=JPU1");
  web_custom_request("JPU1",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

ETRAN;

// 7.3 decode response


  //Decrypt response
 CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    strcat(buffer,"-----END PKCS7-----");
    
    *size=strlen(buffer);

#ifdef DEBUG
    lr_output_message("Tohle je buffer %s",buffer);
	lr_output_message("Size %i",*size);
#endif

  //dekryptov�n� vlastn�
  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

#ifdef DEBUG
  lr_output_message("dekryptov�no size %i\n",*size);
#endif

  output[(*size)]='\0'; //zarovn�n� paddingu

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("dekryptov�no %s\n",output);
  lr_output_message("dekryptov�no %i\n",strlen(output));
#endif

  //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execSPAN",output,"<span id=\"tr_form_debPocaCreate_trn_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"form_debPocaCreate_trn",">"));

  //najdi tagy
  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"form_debPocaCreate_trn","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif

  FREE(output);


// 8.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  sprintf(pom2,"%d",(rand() % 100000)); //kv�li validaci na duplicitn� transakce (variabilni variabilni symbol :-)

#ifdef DEBUG
  lr_output_message("pom2 (VS): %s\n",pom2);
#endif


  MALLOCSTR(pom4,15000); //pom4=(char*)malloc(15000); //buffer pro body

//contracts%3AArangeStart=0&org.apache.myfaces.trinidad.faces.FORM=ib_form&_noJavaScript=false&javax.faces.ViewState=%213&source=contracts%3A2%3AsetContract&state=&value=&contractId=30032668

  strcpy(pom4,"formattedaccount=0");
  strcat(pom4,"&payees=");
  strcat(pom4,"&recaccountprefix=");
  strcat(pom4,"&recaccountnumber=123");
  strcat(pom4,"&recbankcode=0800");
  strcat(pom4,"&amount=10000");
  strcat(pom4,"&constantsymb=");
  strcat(pom4,"&recspecificsymbol=");
  strcat(pom4,"&accountingdate=2/2/2011");
  strcat(pom4,"&messageforrecipient=");
  strcat(pom4,"&messageforprincipal=");
/*  strcat(pom4,"&j_id397=Cross+field+component+fake+value");
  strcat(pom4,"&j_id398=Cross+field+component+fake+value");
  strcat(pom4,"&j_id399=Cross+field+component+fake+value");
  strcat(pom4,"&j_id400=Cross+field+component+fake+value");
  strcat(pom4,"&j_id401=Cross+field+component+fake+value");
  strcat(pom4,"&j_id402=Cross+field+component+fake+value");*/
  strcat(pom4,"&org.apache.myfaces.trinidad.faces.FORM=form_debPocaCreate_trn");
  strcat(pom4,"&_noJavaScript=false");
  strcat(pom4,"&source=doNext");
  strcat(pom4,"&recipientvariablesymbol=");
  strcat(pom4,pom2);
  strcat(pom4,"&javax.faces.ViewState=");
  strcat(pom4,viewState);

#ifdef DEBUG
  lr_output_message("text to encrypt: %s\n",pom4);
#endif

  RET(Encrypt(&output,csas,pom4,strlen(pom4))); //encrypt body

    //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    //  strcpy(buffer,"Value=");
    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

  FREE(output);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  strcpy(pom4,"Body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 8.2 submit

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

BTRAN("B24_JPU_Yellow_Enc");

  addDynaTraceHeader("NA=;PC=JPU2");
  web_custom_request("JPU2",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

ETRAN;

// 8.3 decode response


  //Decrypt response
  CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    strcat(buffer,"-----END PKCS7-----");
    
    *size=strlen(buffer);

#ifdef DEBUG
    lr_output_message("Tohle je buffer %s",buffer);
	lr_output_message("Size %i",*size);
#endif

  //dekryptov�n� vlastn�
  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

#ifdef DEBUG
  lr_output_message("dekryptov�no size %i\n",*size);
#endif

  output[(*size)]='\0'; //zarovn�n� paddingu

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("dekryptov�no %s\n",output);
  lr_output_message("dekryptov�no %i\n",strlen(output));
#endif

  //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execSPAN",output,"<span id=\"tr_form_debPocaCreate_cnf_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"form_debPocaCreate_cnf\"",">"));
  RET(get_param("execSecure",output,"input type=\"hidden\" id=\"transactionToken\"",">"));
  RET(get_param("execPKIContent",output,"id=\"id_pkiContent\" name=\"id_pkiContent\" value=\"","\"")); //convert HTML to text


  //najdi tagy
  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"form_debPocaCreate_cnf","action"));
  RET(searchTag(&nonce,lr_eval_string("{execSecure}"),"transactionToken","value"));

  web_convert_param("execPKIContent", "SourceEncoding=HTML","TargetEncoding=PLAIN", LAST);

  MALLOCSTR(pki_content,strlen(lr_eval_string("{execPKIContent}")));
  strcpy(pki_content,lr_eval_string("{execPKIContent}"));


#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
  lr_output_message("nonce: %s\n",nonce);
  lr_output_message("execPKIcontent: %s\n",pki_content);
#endif

  FREE(output);

//*****///

// 9.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);


  //Encrypt and Sign response

  RET(Sign(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),pki_content,strlen(pki_content),_SHA));
  FREE(pki_content);

  //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

#ifdef DEBUG
  lr_output_message("Vysledek %s",buffer);
  lr_output_message("Delka %d",strlen(buffer));
#endif

  URLencode(&output,buffer);

  MALLOCSTR(pom4,40000); //pom4=(char*)malloc(40000); //buffer pro body

//contracts%3AArangeStart=0&org.apache.myfaces.trinidad.faces.FORM=ib_form&_noJavaScript=false&javax.faces.ViewState=%213&source=contracts%3A2%3AsetContract&state=&value=&contractId=30032668
    strcpy(pom4,"id_pkiContent=");
    strcat(pom4,output);
    strcat(pom4,"&org.apache.myfaces.trinidad.faces.FORM=form_debPocaCreate_cnf");
    strcat(pom4,"&_noJavaScript=false");
    strcat(pom4,"&source=doConfirm"); 
    strcat(pom4,"&transactionToken=");
    strcat(pom4,nonce);
	strcat(pom4,"&javax.faces.ViewState=");
    strcat(pom4,viewState);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("text to encrypt: %s\n",pom4);
#endif

  RET(Encrypt(&output,csas,pom4,strlen(pom4))); //encrypt body

    //find first \n
    p = (char*)strstr(output,"\n");
    i = (int)(p-output);

    MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

    //  strcpy(buffer,"Value=");
    strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

    p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
    *p='\0';

  FREE(output);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  strcpy(pom4,"Body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 9.2 submit

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

BTRAN("B24_JPU_White_Enc");

  addDynaTraceHeader("NA=;PC=JPU3");
  web_custom_request("JPU3",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

ETRAN;

// 9.3 decode response


  //Decrypt response
  CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    strcat(buffer,"-----END PKCS7-----");
    
    *size=strlen(buffer);

#ifdef DEBUG
    lr_output_message("Tohle je buffer %s",buffer);
	lr_output_message("Size %i",*size);
#endif

  //dekryptov�n� vlastn�
  RET(Decrypt(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),buffer,&size));

#ifdef DEBUG
  lr_output_message("dekryptov�no size %i\n",*size);
#endif

  output[(*size)]='\0'; //zarovn�n� paddingu

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("dekryptov�no %s\n",output);
  lr_output_message("dekryptov�no %i\n",strlen(output));
#endif

  //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execRef",output,"Referen&#269;n&iacute; &#269;&iacute;slo transakce je <strong>","</strong>"));

#ifdef DEBUG
  lr_output_message("Referen�n� ��slo transakce je: %s\n",lr_eval_string("{execRef}"));
#endif

  FREE(output);


  FREE(pom3);
  FREE(buffer2);

BTRAN("B24_JPU_Logout_Enc");

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,"/ebanking-b24/ib/base/usr/aut/logout");

  addDynaTraceHeader("NA=;PC=Logout");
  web_url("Logout",
		pom,
		"RecContentType=text/html",
		"Mode=HTML",
		LAST);

ETRAN;




/****

KONEC

****/


konec:
    if(buffer!=NULL) free(buffer);
	if(buffer2!=NULL) free(buffer2);
	if(pki_content!=NULL) free(pki_content);
    if(size!=NULL) free(size);
	if(csas!=NULL) free(csas);  
	i=deallocCA(&output);
#ifdef DEBUG
  lr_output_message("Dealloc CA: %d\n",i);
#endif

#ifdef DEBUG
  ci_set_debug(ci_this_context, 0, 0); /* turn OFF trace & debug */
#endif

  return(0);
}

genADate(char den[])
{
  int day,month,year;
  char temp[20];
  typedef long time_t;
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

  time_t t;
  struct tm *now;

  //_tzset(); // moved to vuser_init()
  time(&t);
  now = (struct tm *)localtime(&t);

  day=now->tm_mday+14;
  month=now->tm_mon+1;
  year=now->tm_year+1900;

  if(day>29)
  {
    day=1;
	month>11?month=1,year++:month++;
  }


  sprintf(temp,"%02i/%02i/%04i",day,month,year); //m�s�c dop�edu splatnost

#ifdef DEBUG
  lr_message("Datum splatnosti: %s",temp);
#endif
  strcpy(den,temp);
}

//get_params from string and save to LR param
int get_param(const char param[],const char input[], const char lb[],const char rb[])
{
  char *output=NULL;
  int ret;

  if((ret=findStr(&output,input,lb,rb))!=0) return(ret);
  lr_save_string(output,param);
  FREE(output);
  return(0);
}

int trimEnd(char input[])
{
  int i;

  i=strlen(input); 
  if((char)(input[i-1])=='\n')
  {
    input[i-1]='\0';
  #ifdef DEBUG
    lr_output_message("Output trimmed; %s",input);
  #endif
    return(1);
  }
  return(0);
}

