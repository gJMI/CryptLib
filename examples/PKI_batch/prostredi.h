//definice parametru pro beh skriptu

#define SERVERURL "http://localhost:7001"
//URL serveru

#define DLL_LOCATION "C:\\Debug\\DecEncDLL.dll"
//cesta k decencdll.dll

//#define DEBUG
//DEBUG output -- podrobny vystup

#define INITTT	#ifndef DEBUG\
  lr_think_time(3);\
  #endif
//initial think time
  
#define BEFTT	#ifndef DEBUG\
  lr_think_time(4);\
  #endif

//think time before transaction
