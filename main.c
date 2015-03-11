#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#define USELESS 0xDEADB00B
#define KEYNUMBER 5
#define FAKESIZE 0xf00ffa00
#define NUMCHECKS 1
//"flag{pack3r_is_4_p4in_in_th3_4ss}"

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



int ENC_sub(int caller, int ebp, int eip, int eips, int a, int b){
    return a-b;
}


int ENC_funtest(int caller, int ebp, int eip, int eips, int a, int b){
    return a+(int)decrypt((void *)ENC_sub, FAKESIZE, b, 1);
}

int ENC_check_header(int caller, int ebp, int eip, int eips, char *key){
    char *header = strstr(key,"flag{");
    if (header == key){
        return 1;
    }
    printf("wrong Header for %s\n", key);
    return 0;
}

int ENC_check(int caller, int ebp, int eip, int eips, int argc, char const *argv[]){
    if (argc <= 1){
        printf("Usage:\n %s flag{<key>}\n", argv[0]);
        exit(0);
    }
    int checks = 0;
    checks +=(int) decrypt((void *) ENC_check_header, FAKESIZE, argv[1]);
    if (checks == NUMCHECKS){
        printf("\033[1;37mYou go the flag: \033[1;32m%s\033[0m\n", argv[1]);
    }
    else{
        printf("\033[1;31mLooser\n\033[0m");
    }
}

int main(int argc, char const *argv[])
{
    decrypt((void *) ENC_check, FAKESIZE, argc, argv);
}