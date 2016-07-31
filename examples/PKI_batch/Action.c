/* PKI nIB B24 zadani ABO davky -- s aplika�n�m/plugin �ifrov�n�m
*  datum splatnosti dopredne
*
*  JMI 2010
*
*  verze: 0.80
*
*/

#include "as_web.h"
#include "prostredi.h"

#define SHA1	0 // defaultn�
#define SHA256	1
#define SHA512	2
#define _SHA	SHA512 //nastaven� SHA

#define DEBUG //zobrazen� DEBUG v�stup�
#define MAXPARAM "160000" //maxim�ln� d�lka parsovan�ho parametru
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

#define PRIKAZNR 6 //prikazu v davce ABO

#define BTRAN(x)  tran=(x);\
  lr_start_transaction((x));
#define ETRAN  lr_end_transaction(tran,LR_AUTO);\
  tran=NULL;

  
genADate(char den[]);
genABO(char ucet[],char out[],int size);
trimEnd(char input[]);
get_param(const char param[],const char input[], const char lb[],const char rb[]);

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
	//ci_set_debug(ci_this_context, 1, 1); /* turn ON trace & debug */
  #endif

	size=(int*)malloc(sizeof(int));

	lr_load_dll(DLL_LOCATION);

	web_set_max_html_param_len(MAXPARAM); //nutn� pro sebran� parametry (databody ~ d�vka ABO)
	web_add_cookie("lang=cs; DOMAIN=localhost");
	web_add_cookie("JSESSIONID=; DOMAIN=localhost");

INITTT;
BTRAN("B24_davka_Login");

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

	MALLOCSTR(csas,strlen(csascert)+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)
	strcpy(csas,"-----BEGIN CERTIFICATE-----\n");
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

	MALLOCSTR(buffer,strlen(output)+10); // pro Value=

	strcpy(buffer,"Value=");
	strcat(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

	p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
	*p='\0';

	FREE(output);

  #ifdef DEBUG
	lr_output_message("Vysledek %s",buffer); 
  #endif

  // First challenge (AJAX challenge)

	web_reg_save_param("response","LB=<RESPONSE>","RB=</RESPONSE>",LAST);

	strcpy(pom,"Action=");
	strcat(pom,SERVERURL);
	strcat(pom,"/ebanking-b24/loginpki");

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
    trimEnd(buffer);
	strcat(buffer,"\n-----END PKCS7-----");

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

	FREE(output);

  #ifdef DEBUG
	lr_output_message("Vysledek %s",buffer); 
  #endif

	strcpy(pom2,"Value=");
	strcat(pom2,nonce);

  #ifdef DEBUG
	lr_output_message("Nonce string %s",pom2); 
  #endif

  //  strcpy(pom,"Action=");
	strcpy(pom,"Action=");
	strcat(pom,SERVERURL);
	strcat(pom,action);

	MALLOCSTR(pom3,strlen(viewState)+15);
	strcpy(pom3,"Value=");
	strcat(pom3,viewState);

ETRAN;

// KONEC p�ihl��en�

// 1. V�b�r kontextu klienta

  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript\">","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"ib_form\"","RB=>",LAST);

//  web_reg_find("Text=P�ehled produkt�",LAST);
  web_submit_data("Login menu Vyber klienta",
       pom, 
       "Method=POST",
       ITEMDATA, 
			  "Name=id_digest_nonce",pom2,ENDITEM,
        "Name=id_pkicert","Value=MIIDYjCCAkqgAwIBA0+mYFniKC2px9miinuLyyvIg07seDiVY/aI\n4pRo1xHQKdYNimJtmMZRxH8d4jvjpSMAiqzqhW7B0qPKrHskIvOs0CjrX2hxtdFuxjqJMiO/YoJ7\nCUXffhgDQnlhLP0uPCsi",ENDITEM, //TO-DO: csascert prom�nn�
			  "Name=id_ajaxUrl","Value=/ebanking-b24/loginpki",ENDITEM,
			  "Name=id_pkicontent", buffer,ENDITEM,
			  "Name=org.apache.myfaces.trinidad.faces.FORM","Value=loginForm",ENDITEM,
			  "Name=_noJavaScript","Value=false",ENDITEM,
			  "Name=javax.faces.ViewState",pom3,ENDITEM,
			  "Name=source","Value=loginBtn",ENDITEM,
       LAST); 

  FREE(buffer);
  FREE(pom3);

//TO-DO

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif

// 2. Login menu -- welcome

// 2.1 P�iprava string�

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom4,15000); //  pom4=(char*)malloc(15000); //buffer pro body

/*
			  "Name=contracts:ArangeStart","Value=0",ENDITEM,
			  "Name=org.apache.myfaces.trinidad.faces.FORM","Value=ib_form",ENDITEM,
			  "Name=_noJavaScript","Value=false",ENDITEM,
			  "Name=javax.faces.ViewState",pom3,ENDITEM,
			  "Name=source","Value=contracts:2:setContract",ENDITEM, //TO-DO index
			  "Name=state","Value=",ENDITEM,
			  "Name=value","Value=",ENDITEM,
			  "Name=contractId","Value=30032668",ENDITEM, //pro� to nejde indexem???
*/
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

  strcpy(pom4,"body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif


// 2.2 submit
/*
  web_submit_data("Login menu -- welcome",
       pom, 
       "Method=POST",
       ITEMDATA, 
			  "Name=contracts:ArangeStart","Value=0",ENDITEM,
			  "Name=org.apache.myfaces.trinidad.faces.FORM","Value=ib_form",ENDITEM,
			  "Name=_noJavaScript","Value=false",ENDITEM,
			  "Name=javax.faces.ViewState",pom3,ENDITEM,
			  "Name=source","Value=contracts:2:setContract",ENDITEM, //TO-DO index
			  "Name=state","Value=",ENDITEM,
			  "Name=value","Value=",ENDITEM,
			  "Name=contractId","Value=30032668",ENDITEM, //pro� to nejde indexem???
       LAST);
*/

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

  web_custom_request("Login Menu Vyber klienta",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);

// 2.3 response decode

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

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"toppane_form","action"));

#ifdef DEBUG
  lr_output_message("viewState: %s\n",viewState);
  lr_output_message("action: %s\n",action);
#endif


// 3. Platebn� styk

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

  strcpy(pom4,"body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif

// 6.2 submit

  web_add_header("X-Content-Encrypted","PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

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

// 4. Import ABO d�vky -- blue screen

// 4.1 P�iprava string�

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

#ifdef DEBUG
  lr_output_message("Pom: %s\n",pom); 
#endif
//tady je chyba

  MALLOCSTR(pom4,1000); //  pom4=(char*)malloc(15000); //buffer pro body

/*
		"Name=org.apache.myfaces.trinidad.faces.FORM", "Value=menu_form", ENDITEM,
		"Name=_noJavaScript", "Value=false", ENDITEM,
		"Name=javax.faces.ViewState",pom3,ENDITEM,
 		"Name=source", "Value=leftMenu:4:leftSubmenu:0:leftSubmenuItem", ENDITEM,
		LAST);

*/
    strcpy(pom4,"org.apache.myfaces.trinidad.faces.FORM=menu_form");
    strcat(pom4,"&_noJavaScript=false");
    strcat(pom4,"&source=leftMenu%3A4%3AleftSubmenu%3A0%3AleftSubmenuItem"); 
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

  FREE(pom4);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  MALLOCSTR(pom4,strlen(output)+500);

  strcpy(pom4,"body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);




// 4.2 Submit

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

BTRAN("B24_davka_Blue");
  web_custom_request("Login Menu Vyber klienta",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom4);


ETRAN;

// 4.3 Response decode

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
  RET(get_param("execSPAN",output,"<span id=\"tr_ib_form_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"ib_form\"",">"));

//  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript\">","RB=</span>",LAST);
//  web_reg_save_param("execAction","LB=form id=\"ib_form","RB=>",LAST);


  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));

#ifdef DEBUG
  lr_output_message("viewstate: %s\n",viewState);
  lr_output_message("execURL: %s\n",action);
#endif

// 5. Import ABO -- 2. blue screen

// 5.1 p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
//  strcat(pom,"/ebanking-b24/ib/base/mapo/imp/create?execution=e6s2");
  strcat(pom,action);

#ifdef DEBUG
  lr_output_message("Pom: %s\n",pom); 
#endif

  MALLOCSTR(buffer,malloc(2000)); //pro ABO davku
  genABO(lr_eval_string("{ClientAccount}"),buffer,PRIKAZNR); //genABO soubor

#ifdef DEBUG
  lr_output_message("ABO d�vka: %s\n",buffer);
  lr_output_message("ABO d�vka d�lka: %i\n",strlen(buffer));
#endif

  MALLOCSTR(pom4,3000);
  strcpy(pom4,"-----------------------------28423275314806\r\n");
  strcat(pom4,"Content-Disposition: form-data; name=\"uploadedfile\"; filename=\"davka.abo\"\r\n");
  strcat(pom4,"Content-Type: application/octet-stream\r\n");
  strcat(pom4,"\r\n");
  strcat(pom4,buffer);
  strcat(pom4,"\r\n");
  strcat(pom4,"-----------------------------28423275314806\r\n");
  strcat(pom4,"Content-Disposition: form-data; name=\"org.apache.myfaces.trinidad.faces.FORM\"\r\n");
  strcat(pom4,"\r\n");
  strcat(pom4,"ib_form\r\n");
  strcat(pom4,"-----------------------------28423275314806\r\n");
  strcat(pom4,"Content-Disposition: form-data; name=\"_noJavaScript\"\r\n");
  strcat(pom4,"\r\n");
  strcat(pom4,"false\r\n");
  strcat(pom4,"-----------------------------28423275314806\r\n");
  strcat(pom4,"Content-Disposition: form-data; name=\"javax.faces.ViewState\"\r\n");
  strcat(pom4,"\r\n");
  strcat(pom4,viewState);
  strcat(pom4,"\r\n-----------------------------28423275314806\r\n");
  strcat(pom4,"Content-Disposition: form-data; name=\"source\"\r\n");
  strcat(pom4,"\r\n");
  strcat(pom4,"doNext\r\n");
  strcat(pom4,"-----------------------------28423275314806--\r\n");
               
  FREE(buffer);

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
  FREE(pom4);

  MALLOCSTR(pom4,strlen(buffer)+220);

//  strcpy(pom4,"-----------------------------28423275314806\r\n");
//  strcat(pom4,buffer);
//  strcat(pom4,"-----------------------------28423275314806--\r\n");
// m�sto toho
  strcpy(pom4,"encdata=");
  strcat(pom4,buffer);

  FREE(buffer);


#ifdef DEBUG
  lr_output_message("Body: %s\n",pom4);
  lr_output_message("Body strlen: %i\n",strlen(pom4));
#endif

// 5.2 submit

  web_add_header("Content-Type","multipart/form-data; boundary=---------------------------28423275314806");
  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

BTRAN("B24_davka_Blue2");

  web_custom_request("ABO2",
		pom,
//		"EncType=",
	    "Method=POST",
		RAW_BODY_START,
		  pom4,
		  strlen(pom4),
		RAW_BODY_END,
		LAST);      

  FREE(pom4);

ETRAN;

// 5.3 decode response

  //Decrypt response
 CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    trimEnd(buffer);
    strcat(buffer,"\n-----END PKCS7-----");
    
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

/*

  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"ib_form\"","RB=>",LAST);
*/

    //dosta� z dekryptovan�ho v�stupu spr�vn� parametry
  RET(get_param("execSPAN",output,"<span id=\"tr_ib_form_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"ib_form",">"));

  //najdi tagy
  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));

#ifdef DEBUG
  lr_output_message("viewstate: %s\n",viewState);
  lr_output_message("execURL: %s\n",action);
#endif

// 6. Import ABO -- yellow screen

// 6.1 P��prava string�

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom3,strlen(viewState)+15);
  strcpy(pom3,"Value=");
  strcat(pom3,viewState);

#ifdef DEBUG
  lr_output_message("Pom: %s\n",pom); 
  lr_output_message("Pom3: %s\n",pom3);
#endif



  MALLOCSTR(pom4,1500); //buffer pro body

	strcpy(pom4,"org.apache.myfaces.trinidad.faces.FORM=ib_form");
	strcat(pom4,"&_noJavaScript=false");
	strcat(pom4,"&ib_table%3ArangeStar=0");
	strcat(pom4,"&source=doNext");
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
  FREE(pom4);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  MALLOCSTR(pom4,strlen(output)+500);
  strcpy(pom4,"body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif


// 6.2 submit

///// PUVODNI


BTRAN("B24_davka_Blue3");
/*
  web_submit_data("ABO3",
		pom,
		"Method=POST",
		ITEMDATA,
		"Name=org.apache.myfaces.trinidad.faces.FORM", "Value=ib_form", ENDITEM,
		"Name=_noJavaScript", "Value=false", ENDITEM,
		"Name=javax.faces.ViewState",pom3,ENDITEM,
 		"Name=source", "Value=doNext", ENDITEM,
		"Name=ib_table:rangeStar", "Value=0", ENDITEM,
		LAST);
*/

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

  web_custom_request("ABO3",
	"Method=POST",
	pom,
	pom4, 
	LAST); 

  FREE(pom3);
  FREE(pom4);

ETRAN;


// 6.3 Decode response

  //Decrypt response
 CHECK(strlen(lr_eval_string("{response}"))>1);
    MALLOCSTR(buffer,strlen(lr_eval_string("{response}"))+(54+10)); //54 pro hlavi�ku, pati�ku; 10 je rezerva (pro '\0' a zbytek pro chybu p�i s��t�n� :-)

    strcpy(buffer,"-----BEGIN PKCS7-----\n");
    strcat(buffer,lr_eval_string("{response}"));
    trimEnd(buffer);
    strcat(buffer,"\n-----END PKCS7-----");
    
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
  RET(get_param("execSPAN",output,"<span id=\"tr_ib_form_Postscript\"","</span>"));
  RET(get_param("execAction",output,"form id=\"ib_form",">"));
  RET(get_param("execSecure",output,"input type=\"hidden\" id=\"transactionToken\"",">"));

/*
  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript\">","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"ib_form","RB=>",LAST);
  web_reg_save_param("execSecure","LB=input type=\"hidden\" id=\"transactionToken\"","RB=>",LAST);
*/

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));
  RET(searchTag(&nonce,lr_eval_string("{execSecure}"),"transactionToken","value"));

#ifdef DEBUG
  lr_output_message("viewstate: %s\n",viewState);
  lr_output_message("execURL: %s\n",action);
  lr_output_message("nonce: %s\n",nonce);
#endif

// 7. Import ABO -- yellow screen

  strcpy(pom,"Action=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

  MALLOCSTR(pom3,strlen(viewState)+15);
  strcpy(pom3,"Value=");
  strcat(pom3,viewState);

  strcpy(pom2,"Value=");
  strcat(pom2,nonce);

#ifdef DEBUG
  lr_output_message("Pom: %s\n",pom); 
  lr_output_message("Pom3: %s\n",pom3);
  lr_output_message("nonce: %s\n",pom2);
#endif
//tady je chyba
  web_reg_save_param("execSPAN","LB=<span id=\"tr_ib_form_Postscript\">","RB=</span>",LAST);
  web_reg_save_param("execAction","LB=form id=\"ib_form","RB=>",LAST);
  web_reg_save_param("execSecure","LB=input type=\"hidden\" id=\"transactionToken\"","RB=>",LAST);
// pki_content 
  web_reg_save_param("execPKIContent","LB=id=\"id_pkiContent\" name=\"id_pkiContent\" value=\"","RB=\"","Convert=HTML_TO_TEXT",LAST);

/*
j_id177%3ArangeStart=0
transactionToken=t5fuEtioGBAWV6AnkkdN
org.apache.myfaces.trinidad.faces.FORM=ib_form
_noJavaScript=false
javax.faces.ViewState=!15
state=
value=
source=doConfirm
*/

BTRAN("B24_davka_Yellow");

  web_submit_data("ABO4",
		pom,
		"Method=POST",
		ITEMDATA,
		"Name=org.apache.myfaces.trinidad.faces.FORM", "Value=ib_form", ENDITEM,
		"Name=j_id177:rangeStart", "Value=0", ENDITEM,
		"Name=_noJavaScript", "Value=false", ENDITEM,
		"Name=javax.faces.ViewState",pom3,ENDITEM,
 		"Name=source", "Value=doConfirm", ENDITEM,
		"Name=ib_table:rangeStar", "Value=0", ENDITEM,
	    "Name=transactionToken", pom2, ENDITEM,
		LAST);

  FREE(pom3);

ETRAN;

  RET(searchTag(&viewState,lr_eval_string("{execSPAN}"),"javax.faces.ViewState","value"));
  RET(searchTag(&action,lr_eval_string("{execAction}"),"ib_form","action"));
  RET(searchTag(&nonce,lr_eval_string("{execSecure}"),"transactionToken","value"));
  MALLOCSTR(pki_content,5000);
  lr_output_message("pki content%s",lr_eval_string("{execPKIContent}"));
  strcpy(pki_content,lr_eval_string("{execPKIContent}"));

#ifdef DEBUG
  lr_output_message("viewstate: %s\n",viewState);
  lr_output_message("execURL: %s\n",action);
  lr_output_message("nonce: %s\n",nonce);
  lr_output_message("pki_content: %s\n",pki_content);
#endif


// 8. ABO -- white screen

// 8.1 -- p��prava string� 

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,action);

#ifdef DEBUG
  lr_output_message("Pom: %s\n",pom); 
  lr_output_message("Pom3: %s\n",pom3);
  lr_output_message("Pom2: %s\n",pom2);
#endif


//Encrypt and Sign response
//  RET(Encrypt(&output,csas,pki_content,strlen(pki_content)));

  RET(Sign(&output,lr_eval_string("{ClientCert}"),lr_eval_string("{ClientKey}"),pki_content,strlen(pki_content),_SHA));
  FREE(pki_content);

//find first \n
  p = (char*)strstr(output,"\n");
  i = (int)(p-output);

  MALLOCSTR(buffer,strlen(output)+10); // pro Value=  

  strcpy(buffer,output+i+1); //copy after -----BEGIN PKCS7-----\n

  p = (char*)strstr(buffer,"-"); //find first occurence of - from --END*
  *p='\0';

  URLencode(&output,buffer);

#ifdef DEBUG
  lr_output_message("Vysledek %s",buffer);
  lr_output_message("Delka %d",strlen(buffer));
  lr_output_message("Vysledek %s",output);
  lr_output_message("Delka %d",strlen(output));
#endif


/*
        "Name=id_pkiContent",buffer, ENDITEM,
	    "Name=transactionToken", pom2, ENDITEM,
		"Name=j_id177:rangeStart", "Value=0", ENDITEM,
	    "Name=org.apache.myfaces.trinidad.faces.FORM", "Value=ib_form", ENDITEM,
		"Name=_noJavaScript", "Value=false", ENDITEM,
		"Name=javax.faces.ViewState", pom3, ENDITEM,
		"Name=source", "Value=doConfirm", ENDITEM,

*/
  MALLOCSTR(pom4,5000);
  strcpy(pom4,"id_pkiContent=");
  strcat(pom4,output);
  strcat(pom4,"&transactionToken=");
  strcat(pom4,nonce);
  strcat(pom4,"&j_id177%3ArangeStart=0");
  strcat(pom4,"&org.apache.myfaces.trinidad.faces.FORM=ib_form");
  strcat(pom4,"&_noJavaScript=false");
  strcat(pom4,"&javax.faces.ViewState=");
  strcat(pom4,viewState);
  strcat(pom4,"&source=doConfirm");

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
  FREE(pom4);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",buffer);
#endif

  URLencode(&output,buffer); //fin�ln� body k odesl�n�

  MALLOCSTR(pom4,strlen(output)+500);
  strcpy(pom4,"body=encdata="); //pro funkci
  strcat(pom4,output);

  FREE(buffer);

#ifdef DEBUG
  lr_output_message("encrypted text: %s\n",output);
  lr_output_message("encrypted text to header: %s\n",pom4);
#endif


// 8.2 submit


BTRAN("B24_davka_White_Enc");
/*
  web_submit_data("ABO5",
		pom,
		"Method=POST",
		"TargetFrame=",
		"RecContentType=text/html",
		"Referer=",
		"Mode=HTML",
		ITEMDATA,
        "Name=id_pkiContent",buffer, ENDITEM,
	    "Name=transactionToken", pom2, ENDITEM,
		"Name=j_id177:rangeStart", "Value=0", ENDITEM,
	    "Name=org.apache.myfaces.trinidad.faces.FORM", "Value=ib_form", ENDITEM,
		"Name=_noJavaScript", "Value=false", ENDITEM,
		"Name=javax.faces.ViewState", pom3, ENDITEM,
		"Name=source", "Value=doConfirm", ENDITEM,
		LAST);
*/

  web_add_header("X-Content-Encrypted","CSAS_PKI1");
  web_reg_save_param("response","LB=<div id=\"EnvelopedData\">","RB=</div>",LAST);

  web_custom_request("ABO5",
    "Method=POST",
    pom,
    pom4, 
    LAST); 

ETRAN;

  FREE(pom3);
  FREE(buffer);

// 8.3 

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


// 9. LOGOUT

BTRAN("B24_davka_Logout");

  strcpy(pom,"URL=");
  strcat(pom,SERVERURL);
  strcat(pom,"/ebanking-b24/ib/base/usr/aut/logout");

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
	if(pom3!=NULL) free(pom3);  
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

genABO(char ucet[],char out[],int size)
{
  int i,day,month,year;
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
  year=now->tm_year-100;

  if(day>29)
  {
    day=1;
	month>11?month=1,year++:month++;
  }

  //free(now); // <-- FUJ

  strcpy(out,"UHL1290305XXXXXXXXXX7325947277001010000000000000\n1 1501 010799 0800\n2 000000-");
  strcat(out,ucet);
  strcat(out," ");
//  strcat(out,"00000000000840"); //sou�et ��stky v hal���ch!!! printf("");
  sprintf(temp,"%014i",size*20);
#ifdef DEBUG
  lr_message("Hal���: %s",temp);
#endif
  strcat(out,temp);
  strcat(out," ");
  sprintf(temp,"%02i%02i%02i",day,month,year); //m�s�c dop�edu splatnost #ifdef DEBUG
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
  //strcat(out,"3 \n5 ");
#ifdef DEBUG
  lr_message("ABO d�vka %s",out); 
#endif
 
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


