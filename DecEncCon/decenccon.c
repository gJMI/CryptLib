#include <windows.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define ENC	0
#define DEC 1

int main(int argc,char** argv)
{
//  typedef UINT (CALLBACK* LPFNDLLFUNC1)(DWORD,UINT); //Encrypt(char *output[],char cert[],char data[],int datasize);
  typedef int (__cdecl* ENCRYPTDLL) (char *output[],char cert[],char data[],int datasize) ;
  typedef int (__cdecl* DECRYPTDLL) (char *output[],char certsigfile[],char privsigfile[],char data[],int **datasize);

  HINSTANCE hDLL;        // Handle to DLL
  ENCRYPTDLL Encrypt;    // Function pointer
  DECRYPTDLL Decrypt;

  int ret,size,action,*fsize=NULL;
  char *output=NULL;
  FILE *f;
  char *cert=NULL,*data=NULL;
  struct _stat status;

  //static char servercertfile[] = "-----BEGIN CERTIFICATE-----\nMIIDYjCCA+mYFniKC2px9miinuLyyvIg07seDiVY/aI4pRo1xHQKdYNimJtmMZRxH8d\n4jvjpSMAiqzqhW7B0qPKrHskIvOs0CjrX2hxtdFuxjqJMiO/YoJ7CUXffhgDQnlh\nLP0uPCsi\n-----END CERTIFICATE-----";

  if (argc==1)
  {
	  printf("TODO -- HELP!\n");
	  printf("Encrypt\ndecenccon.exe e certfile datafile\n");
	  printf("Decrypt\ndecenccon.exe d certsigfile privsigfile datafile\n");
	  return(1);
  }

  switch((argv[1])[0])
  {
    case 'e': action=ENC;break;
	case 'd': action=DEC;break;
	default: return(1);
  }

  hDLL = LoadLibrary("DecEncDLL.dll"); // L"string"
  if(hDLL == NULL) return(1);

  if(action==ENC) //read cert for encoding
  {
    f=fopen(argv[2],"rt"); //TODO
    if(f==NULL) return(2);
	  ret=_fileno(f);
	  ret=_fstat(_fileno(f),&status); //lenght of file (?)
//    printf("Size of file is %d\n",status.st_size);
      cert=malloc(sizeof(char)*status.st_size);
      size=(int)fread(cert,sizeof(char),status.st_size,f);
    fclose(f);
  }

  fsize=(int*)malloc(sizeof(int)); //for decrypt

    switch(action)
    {
	  case ENC: f=fopen(argv[3],"r"); break; //read data
	  case DEC: f=fopen(argv[4],"r"); break;
    }
    
	if(f==NULL) return(3);

    ret=_fileno(f);
	ret=_fstat(_fileno(f),&status); //lenght of file (?)
//    printf("Size of file is %d\n",status.st_size);
    data=(char*)malloc(sizeof(char)*status.st_size);
    size=(int)fread(data,sizeof(char),status.st_size,f);
    *fsize=size;
  fclose(f);

  Encrypt = (ENCRYPTDLL)GetProcAddress(hDLL,"Encrypt");
  Decrypt = (DECRYPTDLL)GetProcAddress(hDLL,"Decrypt");

  if (!Encrypt || !Decrypt) goto konec;
     
  switch(action)
  {
	case ENC: ret=Encrypt(&output,cert,data,size);break;
	case DEC: ret=Decrypt(&output,argv[2],argv[3],data,&fsize);output[(*fsize)]='\0';break;
  }
  if (ret==0) fputs(output,stdout);

konec:
  FreeLibrary(hDLL);
  free(data);
  free(fsize);
  if(action==ENC) free(cert);
  free(output);
  return(0);
}

