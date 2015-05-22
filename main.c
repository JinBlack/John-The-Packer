#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define USELESS 0xDEADB00B
#define KEYNUMBER 5
#define FAKESIZE 0xf00ffa00
#define NUMCHECKS 7
#define CHECK2SIZE 11

// #define DEBUG

//"flag{packer-15-4-?41=-in-th3-4ss}"

char *keys[KEYNUMBER] = {"\x01\x02\x03\x04", "\x10\x20\x30\x40", "B00B", "DEAD", "\xff\xff\xff\xff"};


typedef void* func(void);

void *encrypt(void *called, int length, ...){
   __asm__
   ("push %%eax;\n" //Save the result before encryption
    :/*no output*/
    :/* %1: In */
    :/**/
   );

   __asm__
   ("mov (%%edx), %%edx;\n"
    "loopE:"
    "xor %%edx, (%%ebx);\n"
    "add $4, %%ebx;\n"
    "dec %%ecx;\n"
    "jnz loopE;\n"
    "pop %%eax;\n" //Restore the result.
    :/*no output*/
    :"b" (called), "c" (length), "d" (keys[((int)called) % KEYNUMBER]) /* %1: In */
    :
   );
}


void *decrypt(void *called, int length, ...){
    mprotect((void *) (((unsigned int)called) & 0xfffff000), 0x1000, PROT_WRITE | PROT_READ | PROT_EXEC);
   __asm__
   ("add $8, %%esp;\n"
    "push %%eax;\n"
    "mov (%%edx), %%edx;\n"
    "loopD:"
    "xor %%edx, (%%eax);\n"
    "add $4, %%eax;\n"
    "dec %%ecx;\n"
    "jnz loopD;\n"
    "pop %%eax;\n"
    "call %%eax;\n"
    :/*no output*/
    :"a" (called), "c" (length), "d" (keys[((int)called) % KEYNUMBER]) /* %1: In */
    :/* no clobbers*/
   );
   encrypt(called, length);
}



int ENC_check_header(int caller, int ebp, int eip, int eips, char *key){
    char *header = strstr(key,"flag{");
    if (header == key){
        return 1;
    }
    printf("wrong Header for %s\n", key);
    return 0;
}


int ENC_check_footer(int caller, int ebp, int eip, int eips, char *key){
    if ('}' == *(key+strlen(key)-1)){
        return 1;
    }
    printf("wrong End for %s\n", key);
    return 0;
}


int ENC_check_ascii(int caller, int ebp, int eip, int eips, char *key){
    int l = strlen(key);
    int i;
    for (i=0; i < l; i++){
        if (!isascii(key[i])){
            printf("Not ascii character in %s\n", key);
            return 0;            
        }
    }
    return 1;
}

int ENC_eq(int caller, int ebp, int eip, int eips, int x){
    float a = pow(x, 5) * 0.5166666688 - pow(x, 4) *8.125000037 + pow(x, 3)*45.83333358 - pow(x, 2) * 109.8750007 + x * 99.65000093 + 83.99999968;
    return (int) a;
}

int ENC_func(int caller, int ebp, int eip, int eips, int x,unsigned long long y){
    unsigned long long a = 4* (unsigned long long)pow(2,x) + 21;
    // printf("%c %llu %llu\n",x, a, y);
    return a==y;
}


int ENC_len(int caller, int ebp, int eip, int eips, char *key){
	if (strlen(key) == 33)
		return 1;
	return 0;
}


int ENC_check3(int caller, int ebp, int eip, int eips, char *key, int i){
    const char *test = "\x10\x44\x07\x43\x59\x1c\x5b\x1e\x19\x47\x00";
    char a,b;
    #ifdef DEBUG
        printf("iter: %d len: %d\n",i, strlen(key) );
    #endif

    if (i+CHECK2SIZE+11 >= strlen(key)){
        return 1;
    }
    a = test[i] ^ key[10+CHECK2SIZE+i-1];
    b = key[10+CHECK2SIZE+i];
    #ifdef DEBUG
        printf("t:%x k-1:%c t^k-1:%x != k:%x\n",test[i], key[10+CHECK2SIZE+i-1] ,a, b);
    #endif

    if (a != b){
        #ifdef DEBUG
            printf("Fail\n");
        #endif
        return 0;
    }
    #ifdef DEBUG
        printf("Next Step\n");
    #endif

    return ENC_check3(USELESS, USELESS, USELESS, USELESS, key, i+1);
}


int ENC_check2(int caller, int ebp, int eip, int eips, char *key){
    unsigned long long value[CHECK2SIZE] = {140737488355349,
                                            2251799813685269,
                                            36028797018963989,
                                            140737488355349,
                                            18014398509482005,
                                            140737488355349,
                                            36893488147419103253,
                                            18014398509482005,
                                            2251799813685269,
                                            9223372036854775829,
                                            140737488355349};
    int i;

    for (i=0; i < CHECK2SIZE; i++){
        // printf("value %d: %llu\n",i, value[i]);
       if (!decrypt((void *) ENC_func, FAKESIZE, (int)key[11+i], value[i])){
            return 0;
       }
    }
    return 1;
}



int ENC_check1(int caller, int ebp, int eip, int eips, char *key){
    int l = 6;
    int i;

    for (i=1; i <= l; i++){
       if ((int)key[4+i] != (int)decrypt((void *) ENC_eq, FAKESIZE, i)){
        return 0;
       }
    }
    return 1;
}



int ENC_check(int caller, int ebp, int eip, int eips, int argc, char const *argv[]){
    if (argc <= 1){
        printf("Usage:\n %s flag{<key>}\n", argv[0]);
        exit(0);
    }
    int checks = 0;
    checks +=(int) decrypt((void *) ENC_check_header, FAKESIZE, argv[1]);
    checks +=(int) decrypt((void *) ENC_check_footer, FAKESIZE, argv[1]);
    checks +=(int) decrypt((void *) ENC_check_ascii, FAKESIZE, argv[1]);
    checks +=(int) decrypt((void *) ENC_check1, FAKESIZE, argv[1]);
    checks +=(int) decrypt((void *) ENC_check2, FAKESIZE, argv[1]);
    checks +=(int) decrypt((void *) ENC_check3, FAKESIZE, argv[1], 0);
    checks +=(int) decrypt((void *) ENC_len, FAKESIZE, argv[1]);

    if (checks == NUMCHECKS){
        printf("\033[1;37mYou got the flag: \033[1;32m%s\033[0m\n", argv[1]);
    }
    else{
        printf("\033[1;31mLoser\n\033[0m");
    }
}

int main(int argc, char const *argv[])
{
    decrypt((void *) ENC_check, FAKESIZE, argc, argv);
}