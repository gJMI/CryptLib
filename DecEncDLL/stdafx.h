// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>



// TODO: reference additional headers your program requires here
/*
__declspec(dllexport) int init();
__declspec(dllexport) int Encrypt(char *output[],char cert[],char data[],int datasize);
__declspec(dllexport) int SignEncrypt(char *output[],char certencfile[],char certsigfile[], char privsigfile[],char data[],int datasize);
__declspec(dllexport) int Decrypt(char *output[],char certsigfile[],char privsigfile[],char data[],int **datasize);
*/

int init();
int Encrypt(char *output[],char cert[],char data[],int datasize);
int SignEncrypt(char *output[],char certencfile[],char certsigfile[], char privsigfile[],char data[],int datasize);
int Decrypt(char *output[],char certsigfile[],char privsigfile[],char data[],int **datasize);
int deallocCA(char *output[]);
int digestSHA1(char *output[],unsigned char input[],int size);
int searchTag(char *output[], char input[], char tag[], char value[]);
int Sign(char *output[],char certsigfile[], char privsigfile[],char data[],int datasize);
int URLencode(char *output[],const char original[]);
int findStr(char *output[],const char input[], const char lb[],const char rb[]);