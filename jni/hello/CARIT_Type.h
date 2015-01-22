#ifndef _CARIT_TYPE_H_
#define _CARIT_TYPE_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned char CARIT_U8;
typedef unsigned short CARIT_U16;
typedef unsigned int CARIT_U32;

typedef char  CARIT_S8;
typedef short CARIT_S16;
typedef int   CARIT_S32;
typedef float CARIT_float;

typedef CARIT_U32  CARIT_HANDLE;

#define CARIT_OK 0
#define CARIT_FAIL -1

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifdef __cplusplus
}
#endif

#endif //_CARIT_TYPE_H_

