/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу xtsmac - режима шифрования с аутентификацией.

   test-xstmac.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <libakrypt.h>
 #include <libakrypt-internal.h>

/* Kлюч (закомментированы значения, скопированные из текста рекомендаций )
   88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF */

 static ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

/*  A:
   ­ 02 02 02 02 02 02 02 02 01 01 01 01 01 01 01 01
    04 04 04 04 04 04 04 04 03 03 03 03 03 03 03 03
    EA 05 05 05 05 05 05 05 05                       */
 static ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

/*­  P:
    11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88
    00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
    11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
    22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11
    AA BB CC                                        */
 static ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

/* ­ nonce:
    11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 */
 static ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

 int main( void )
{
  int result;
  ak_uint8 out[ sizeof( plain )], out2[ sizeof( plain )], icode[16];
  struct bckey key; /* ключ блочного алгоритма шифрования */

  memset( out, 0, sizeof( out ));
  memset( out2, 0, sizeof( out2 ));

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* инициализируем ключ */
  ak_bckey_create_kuznechik( &key );
  ak_bckey_set_key( &key, keyAnnexA, sizeof( keyAnnexA ));

  printf("using cipher: %s (%s)\n", key.key.oid->name[0], key.key.oid->id[0] );

 /* зашифровываем данные и одновременно вычисляем имитовставку */
  ak_bckey_encrypt_xtsmac(
    &key,              /* ключ, используемый для шифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    associated,             /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
    plain,                  /* указатель на зашифровываемые данные */
    out,                            /* указатель на область памяти,
                         в которую помещаются зашифрованные данные */
    sizeof( plain ),              /* размер зашифровываемых данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
    icode,                          /* указатель на область памяти,
                                 в которую помещается имитовставка */
    sizeof( icode )                         /* размер имитовставки */
  );

  printf("enc:   %s\n", ak_ptr_to_hexstr( out, sizeof(out), ak_false ));
  printf("icode: %s\n\n", ak_ptr_to_hexstr( icode, sizeof(icode), ak_false ));

 /* расшифровываем данные и одновременно проверяем имитовставку */
  result = ak_bckey_decrypt_xtsmac(
    &key,              /* ключ, используемый для шифрования данных */
    &key,             /* ключ, используемый для имитозащиты данных */
    associated,             /* указатель на ассоциированные данные */
    sizeof( associated ),          /* длина ассоциированных данных */
    out,                   /* указатель на расшифровываемые данные */
    out2,                           /* указатель на область памяти,
                        в которую помещаются расшифрованные данные */
    sizeof( plain ),              /* размер зашифровываемых данных */
    iv128,             /* синхропосылка (инициализационный вектор) */
    sizeof( iv128 ),                       /* размер синхропосылки */
    icode,                          /* указатель на область памяти,
                                 в которую помещается имитовставка */
    sizeof( icode )                         /* размер имитовставки */
  );

  if( result != ak_error_ok ) {
    printf("result is Wrong (code: %d)\n", result );
  } else printf("result (icode checking) is Ok\n");

  printf("\nout2:  %s\n", ak_ptr_to_hexstr( out2, sizeof(out2), ak_false ));
  printf("plain: %s\n", ak_ptr_to_hexstr( plain, sizeof(plain), ak_false ));

  if( !ak_ptr_is_equal_with_log( out2, plain, sizeof( plain ))) {
    printf("data is not equal (code: %d)\n", result = ak_error_not_equal_data );
  }

 /* уничтожаем контекст ключа */
  ak_bckey_destroy( &key );
  ak_libakrypt_destroy();

 if( result == ak_error_ok ) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
