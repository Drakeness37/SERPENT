/* Тестовый пример

   test-serpent.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libakrypt.h>

#include "../source/ak_serpent.c"


int main( void )
{
    struct bckey bkey;
    ak_uint8 myout1[16], myout2[16];

    ak_uint8 key[32] = {
            0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,
            0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88
    };
    ak_uint8 in[16] = {
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11
    };
    printf("TEST SERPENT!!!\n");
    ak_bckey_create_serpent( &bkey );
    ak_bckey_set_key( &bkey, key,
                      sizeof( key ));
    bkey.encrypt( &bkey.key, in, myout1 );
    bkey.decrypt( &bkey.key, myout1, myout2 );
    bkey.delete_keys(&bkey.key);
    if (memcmp(in, myout2, 16)) {
        printf("\nFail\n");
        return EXIT_FAILURE;
    } else {
        printf("\nSuccess\n");
        return EXIT_SUCCESS;
    }
}

