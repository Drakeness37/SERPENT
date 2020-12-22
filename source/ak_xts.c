/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_xts.c                                                                                  */
/*  - содержит реализацию режимов шифрования, построенных по принципу гамма-коммутатор-гамма.      */
/*     подробности смотри в IEEE P 1619,                                                           */
/*     а также в статье https://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

#ifdef AK_HAVE_STDALIGN_H
 #include <stdalign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует алгоритм двухключевого шифрования, описываемый в стандарте IEEE P 1619.

    \note Для блочных шифров с длиной блока 128 бит реализация полностью соответствует
    указанному стандарту. Для шифров с длиной блока 64 реализация использует преобразования,
    в частности вычисления к конечном поле \f$ \mathbb F_{2^{128}}\f$,
    определенные для 128 битных шифров.

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (открытые) данные
    @param out Указатель на область памяти, куда будут помещены зашифровываемые данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
  alignas(16)
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->encrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->encrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* нижеследующий фрагмент выглядит более современно,
   но дает скорость на 0.5 МБ в секунду медленнее.
   возможно, я что-то делаю совсем не так....

   #include <immintrin.h>

   _m128i gamma = _mm_set_epi64x( tweak[1], tweak[0] );
   _m128i data = _mm_set_epi64x( *(inptr+1), *inptr ); inptr += 2;

         data = _mm_xor_si128( data, gamma );
         encryptionKey->encrypt( &encryptionKey->key, &data, &data );
         data = _mm_xor_si128( data, gamma );
         *outptr = _mm_extract_epi64( data, 0 ); outptr++;
         *outptr = _mm_extract_epi64( data, 1 ); outptr++;
         --blocks;                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует обратное преобразование к алгоритму, реализуемому с помощью
    функции ak_bckey_encrypt_xts().

    @param encryptionKey Ключ, используемый для шифрования информации
    @param authenticationKey Ключ, используемый для преобразования синхропосылки и выработки
    псевдослучайной последовательности
    @param in Указатель на область памяти, где хранятся входные (зашифрованные) данные
    @param out Указатель на область памяти, куда будут помещены расшифрованные данные
    @param size Размер входных данных (в октетах)
    @param iv Указатель на область памяти, где находится синхропосылка (произвольные данные).
    @param iv_size Размер синхропосылки в октетах, должен быть отличен от нуля.
    Если размер синхропосылки превышает 16 октетов (128 бит), то оставшиеся значения не используются.

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xts( ak_bckey encryptionKey,  ak_bckey authenticationKey,
                        ak_pointer in, ak_pointer out, size_t size, ak_pointer iv, size_t iv_size )
{
  int error = ak_error_ok;
  ak_int64 jcnt = 0, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)in, *outptr = (ak_uint64 *)out;
#ifdef AK_HAVE_STDALIGN_H
  alignas(16)
#endif
  ak_uint64 tweak[2], t[2], *tptr = t;

 /* проверяем целостность ключа */
  if( encryptionKey->key.check_icode( &encryptionKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                               "incorrect integrity code of encryption key value" );
  if( authenticationKey->key.check_icode( &authenticationKey->key ) != ak_true )
    return ak_error_message( ak_error_wrong_key_icode, __func__,
                                           "incorrect integrity code of authentication key value" );

 /* проверяем ресурс ключа аутентификации */
  if( authenticationKey->key.resource.value.counter < (ssize_t)( authenticationKey->bsize >> 3 ))
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of authentication cipher key" );
   else authenticationKey->key.resource.value.counter -= ( authenticationKey->bsize >> 3 );

 /* вырабатываем начальное состояние вектора */
  memset( tweak, 0, sizeof( tweak ));
  memcpy( tweak, iv, ak_min( iv_size, sizeof( tweak )));

  if( authenticationKey->bsize == 8 ) {
    authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );
    tweak[1] ^= tweak[0];
    authenticationKey->encrypt( &authenticationKey->key, tweak+1, tweak+1 );
  } else
      authenticationKey->encrypt( &authenticationKey->key, tweak, tweak );

 /* вычисляем количество блоков */
  blocks = ( ak_int64 )( size/encryptionKey->bsize );
  if( size != blocks*encryptionKey->bsize )
    return ak_error_message( ak_error_wrong_block_cipher_length,
                            __func__ , "the length of input data is not divided by block length" );

 /* изменяем ресурс ключа */
  if( encryptionKey->key.resource.value.counter < blocks )
    return ak_error_message( ak_error_low_key_resource,
                                              __func__ , "low resource of encryption cipher key" );
   else encryptionKey->key.resource.value.counter -= blocks;

 /* запускаем основной цикл обработки блоков информации */
   switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          *tptr = *inptr^*(tweak+jcnt); inptr++;
          encryptionKey->decrypt( &encryptionKey->key, tptr, tptr );
          *outptr = *tptr ^ *(tweak+jcnt); outptr++;
          --blocks;
          tptr++;

          if( !(jcnt = 1 - jcnt)) { /* изменяем значение tweak */
            tptr = t;
            t[0] = tweak[0] >> 63; t[1] = tweak[1] >> 63;
            tweak[0] <<= 1; tweak[1] <<= 1;
            tweak[1] ^= t[0];
            if( t[1] ) tweak[0] ^= 0x87;
          }
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
         /* шифруем */
          t[0] = *inptr^*tweak; inptr++;
          t[1] = *inptr^*(tweak+1); inptr++;

          encryptionKey->decrypt( &encryptionKey->key, t, t );
          *outptr = t[0]^*tweak; outptr++;
          *outptr = t[1]^*(tweak+1); outptr++;
          --blocks;

         /* изменяем значение tweak */
          t[0] = tweak[0] >> 63;
          t[1] = tweak[1] >> 63;
          tweak[0] <<= 1;
          tweak[1] <<= 1;
          tweak[1] ^= t[0];
          if( t[1] ) tweak[0] ^= 0x87;
       }
       break;
   }

 /* очищаем */
  if(( error = ak_ptr_wipe( tweak, sizeof( tweak ), &encryptionKey->key.generator )) != ak_error_ok )
   ak_error_message( error, __func__ , "wrong wiping of tweak value" );

 /* перемаскируем ключ */
  if(( error = encryptionKey->key.set_mask( &encryptionKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of encryption key" );
  if(( error = authenticationKey->key.set_mask( &authenticationKey->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "wrong remasking of authentication key" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                 реализация режима аутентифицирующего шифрования xtsmac                          */
/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup aead-doc
 @{ */
/*! \brief Структура, содержащая текущее состояние внутренних переменных режима `xtsmac`
   аутентифицированного шифрования. */
 typedef struct xtsmac_ctx {
  /*! \brief Текущее значение имитовставки. */
   ak_uint64 sum[2];
  /*! \brief Вектор, используемый для маскирования шифруемой информации. */
   ak_uint64 gamma[6];
  /*! \brief Размер обработанных зашифровываемых/расшифровываемых данных в битах. */
   ssize_t pbitlen;
  /*! \brief Размер обработанных ассоциированных данных в битах. */
   ssize_t abitlen;
  /*! \brief Флаги состояния контекста. */
   ak_uint32 flags;
} *ak_xtsmac_ctx;
/** @} */

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_clean( ak_xtsmac_ctx ctx,
                            ak_bckey authenticationKey, const ak_pointer iv, const size_t iv_size )
{
  int error = ak_error_ok;
  ak_uint64 lvector[6] = { 0, 0, 0, 0, 0, 0 };
  ak_uint8 liv[16] = { 0x35, 0xea, 0x16, 0xc4, 0x06, 0x36, 0x3a, 0x30,
                        0xbf, 0x0b, 0x2e, 0x69, 0x39, 0x92, 0xb5, 0x8f }; /* разложение числа pi,
                                                                           начиная с 100000 знака */
 if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if( !iv_size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using initial vector of zero length" );
 /* обнуляем необходимое */
  memset( ctx, 0, sizeof( struct xtsmac_ctx ));

 /* формируем значение gamma */
  memcpy( lvector, iv, ak_min( iv_size, 16 ));
  if(( error = ak_bckey_encrypt_cbc( authenticationKey, lvector,
                               ctx->gamma, sizeof( lvector ), liv, sizeof( liv ))) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect initialization of gamma values" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_next_gamma { \
            t[0] = ctx->gamma[0] >> 63; t[1] = ctx->gamma[1] >> 63; \
            ctx->gamma[0] <<= 1; ctx->gamma[1] <<= 1; \
            ctx->gamma[1] ^= t[0]; \
            if( t[1] ) ctx->gamma[0] ^= 0x87; \
         }

 #define ak_xtsmac_update_sum { \
            t[0] ^= ctx->gamma[2]; \
            v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
            v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
            v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
            v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
            v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
            v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
            v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
            v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
            t[1] ^= v; \
            t[1] ^= ctx->gamma[3]; \
            v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
            v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
            v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
            v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
            v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
            v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
            v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
            v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
            t[0] ^= v; \
            t[0] ^= ctx->gamma[4]; \
            v  = streebog_Areverse_expand_with_pi[0][tb[ 0]]; \
            v ^= streebog_Areverse_expand_with_pi[1][tb[ 1]]; \
            v ^= streebog_Areverse_expand_with_pi[2][tb[ 2]]; \
            v ^= streebog_Areverse_expand_with_pi[3][tb[ 3]]; \
            v ^= streebog_Areverse_expand_with_pi[4][tb[ 4]]; \
            v ^= streebog_Areverse_expand_with_pi[5][tb[ 5]]; \
            v ^= streebog_Areverse_expand_with_pi[6][tb[ 6]]; \
            v ^= streebog_Areverse_expand_with_pi[7][tb[ 7]]; \
            t[1] ^= v; \
            t[1] ^= ctx->gamma[5]; \
            v  = streebog_Areverse_expand_with_pi[0][tb[ 8]]; \
            v ^= streebog_Areverse_expand_with_pi[1][tb[ 9]]; \
            v ^= streebog_Areverse_expand_with_pi[2][tb[10]]; \
            v ^= streebog_Areverse_expand_with_pi[3][tb[11]]; \
            v ^= streebog_Areverse_expand_with_pi[4][tb[12]]; \
            v ^= streebog_Areverse_expand_with_pi[5][tb[13]]; \
            v ^= streebog_Areverse_expand_with_pi[6][tb[14]]; \
            v ^= streebog_Areverse_expand_with_pi[7][tb[15]]; \
            t[0] ^= v; \
            ctx->sum[0] ^= t[0]; \
            ctx->sum[1] ^= t[1]; \
         }

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_authenticate_step64( in ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            authenticationKey->encrypt( &authenticationKey->key, t, t ); \
            authenticationKey->encrypt( &authenticationKey->key, t+1, t+1 ); \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum; \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_encrypt_step64( in, out ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            encryptionKey->encrypt( &encryptionKey->key, t, t ); \
            encryptionKey->encrypt( &encryptionKey->key, t+1, t+1 ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_decrypt_step64( in, out ) { \
            t[0] = temp[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = temp[1] = *(in)^ctx->gamma[1]; (in)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* расшифровываем данные */ \
            encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
            encryptionKey->decrypt( &encryptionKey->key, temp+1, t+1 ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
            ak_xtsmac_next_gamma; \
         }

/* ----------------------------------------------------------------------------------------------- */
 #define ak_xtsmac_authenticate_step128( in ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            authenticationKey->encrypt( &authenticationKey->key, t, t ); \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_encrypt_step128( in, out ) { \
            t[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = *(in)^ctx->gamma[1]; (in)++; \
            encryptionKey->encrypt( &encryptionKey->key, t, t ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

 #define ak_xtsmac_decrypt_step128( in, out ) { \
            t[0] = temp[0] = *(in)^ctx->gamma[0]; (in)++; \
            t[1] = temp[1] = *(in)^ctx->gamma[1]; (in)++; \
           /* вычисляем слагаемое для имитовставки */ \
            ak_xtsmac_update_sum;  \
           /* расшифровываем данные */ \
            encryptionKey->decrypt( &encryptionKey->key, temp, t ); \
            *(out) = t[0]^ctx->gamma[0]; (out)++; \
            *(out) = t[1]^ctx->gamma[1]; (out)++; \
           /* изменяем значение гаммы */ \
            ak_xtsmac_next_gamma; \
         }

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_update( ak_xtsmac_ctx ctx,
                      ak_bckey authenticationKey, const ak_pointer adata, const size_t adata_size )
{
  register ak_uint64 v = 0;
  const ak_uint64 *inptr = (const ak_uint64 *)adata;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)&t;
  ssize_t tail = ( ssize_t )( adata_size&0xf ),
          blocks = ( ssize_t )( adata_size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( authenticationKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_assosiated_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( authenticationKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else authenticationKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( authenticationKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          ak_xtsmac_authenticate_step64( inptr );
          ctx->abitlen += 128;
          --blocks;
       }
       if( tail ) {
          ak_uint64 *tptr = temp;
          memcpy( temp, inptr, tail ); /* копируем входные данные (здесь меньше одного 16-ти байтного блока) */
          ak_xtsmac_authenticate_step64( tptr );
          ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
          ctx->abitlen += ( tail << 3 );
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
          ak_xtsmac_authenticate_step128( inptr );
          ctx->abitlen += 128;
          --blocks;
       }
       if( tail ) {
          ak_uint64 *tptr = temp;
          memcpy( temp, inptr, tail ); /* копируем входные данные */
          ak_xtsmac_authenticate_step128( tptr );
          ak_aead_set_bit( ctx->flags, ak_aead_assosiated_data_bit );
          ctx->abitlen += ( tail << 3 );
       }
       break;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Для завершения процесса вычисления имитовставки мы применяем процедуру шифрования
    для специального блока, который формируется из длин обработаных данных `plen || alen`.
    Результат шифрования подсуммируется к общей контрольной сумме.

    Последним шагом вычисления имитовставки является операция наложения гаммы и зашифрование
    вычисленной контрольной суммы. Полученное в ходе шифрования значение и является результирующим
    значением имитовставки. Формально, реализуемое преобразование может быть описано
    следующим образом

    \f[ \Sigma = \Sigma \oplus \Pi( \texttt{ECB}( K_A, ( \texttt{plen}||\texttt{alen}) \oplus \gamma_{n+1})), \f]

    \f[ Im = \texttt{ECB}( K_A, \Sigma \oplus \gamma_{n+2} ), \f]

    где, как и ранее, `ECB` это режим простой замены,
    \f$ \Pi \f$ - используемое в алгоритме перемешивающее преобразование,
    а `n` это количество 16-ти байтных блоков, преобразованных ранее.
    Во всех операциях шифрования используется ключ аутентификации \f$ K_A \f$.

    \param ctx
    \param authenticationKey
    \param out
    \param out_size
    \return В случае успеха функция возвращает ak_error_ok (ноль).
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_authentication_finalize( ak_xtsmac_ctx ctx,
                               ak_bckey authenticationKey, ak_pointer out, const size_t out_size )
{
  register ak_uint64 v;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2];
  ak_uint8 *tb = (ak_uint8 *)&t;

  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to output buffer" );
 /* проверка запрашиваемой длины iv */
  if( out_size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                      "unexpected zero length of integrity code" );
 /* проверка длины блока */
  if( authenticationKey->bsize > 16 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using key with large block size" );
  /* традиционная проверка ресурса */
  if( authenticationKey->key.resource.value.counter <= 0 )
    return ak_error_message( ak_error_low_key_resource, __func__,
                                                                "using key with low key resource");
   else authenticationKey->key.resource.value.counter--;

 /* закрываем добавление шифруемых данных */
   ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );

 /* формируем последний вектор из длин, записанных в big-endian формате */
#ifdef AK_BIG_ENDIAN
    t[0] = ( ak_uint64 )ctx->pbitlen;
    t[1] = ( ak_uint64 )ctx->abitlen;
#else
    t[0] = bswap_64(( ak_uint64 )ctx->pbitlen );
    t[1] = bswap_64(( ak_uint64 )ctx->abitlen );
#endif
    t[0] ^= ctx->gamma[0];
    t[1] ^= ctx->gamma[1];

  if( authenticationKey->bsize == 8 ) {
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
     authenticationKey->encrypt( &authenticationKey->key, t+1, t+1 ); \
    /* вычисляем слагаемое для имитовставки */ \
     ak_xtsmac_update_sum;
    /* изменяем значение гаммы */
     ak_xtsmac_next_gamma;
    /* последнее шифрование и завершение работы */
     ctx->sum[0] ^= ctx->gamma[0];
     ctx->sum[1] ^= ctx->gamma[1];
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum+1, &ctx->sum+1 );

  } else { /* теперь тоже самое, но для 128-битного шифра */
     authenticationKey->encrypt( &authenticationKey->key, t, t ); \
    /* вычисляем слагаемое для имитовставки */ \
     ak_xtsmac_update_sum;
    /* изменяем значение гаммы */
     ak_xtsmac_next_gamma;
    /* последнее шифрование и завершение работы */
     ctx->sum[0] ^= ctx->gamma[0];
     ctx->sum[1] ^= ctx->gamma[1];
     authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
  }

 /* если памяти много (out_size >= 16), то копируем все, что есть, */
            /* в противном случае - только ту часть, что вмещается */
  memcpy( out, ((ak_uint8 *)ctx->sum)+( out_size >= 16 ? 0 : 16 - out_size ),
                                                                           ak_min( out_size, 16 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_encryption_update( ak_xtsmac_ctx ctx, ak_bckey encryptionKey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  register ak_uint64 v = 0;
  ak_uint64 *outptr = (ak_uint64 *)out;
  const ak_uint64 *inptr = (const ak_uint64 *)in;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)t;
  ssize_t i = 0,
          tail = ( ssize_t )( size&0xf ),
          blocks = ( ssize_t )( size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( encryptionKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail > 0 ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
            "xtsmac mode unsupport short messages (length must be equal or more than block size)");
 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( encryptionKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else encryptionKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > 0 ) {
          ak_xtsmac_encrypt_step64( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > 0 ) {
          ak_xtsmac_encrypt_step128( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;
  }

  if( tail ) { /* реализуем "скрадывание" шифртекста таким образом, чтобы длина шифртекста
                                                                   совпадала с длиной открытого  */
    size_t adlen = 16 - tail;
    ak_uint64 *tpi = (ak_uint64 *)t, *tpo = (ak_uint64 *)temp;
   /* формируем дополнительный полный блок */
    memcpy( tb, inptr, tail );
    memcpy( tb + tail, ((ak_uint8 *)outptr) - adlen, adlen );
   /* шифруем полученное */
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_encrypt_step64( tpi, tpo ); }
     else { ak_xtsmac_encrypt_step128( tpi, tpo ); }
   /* размещаем по ячейкам */
    for( i = 0; i < tail; i++ ) ((ak_uint8* )outptr)[i] = ((ak_uint8 *)(outptr-2))[i];
       *(outptr-2) = temp[0];
       *(outptr-1) = temp[1];
       ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
       ctx->pbitlen += ( tail << 3 );
    }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_xtsmac_decryption_update( ak_xtsmac_ctx ctx, ak_bckey encryptionKey,
                                          const ak_pointer in, ak_pointer out, const size_t size )
{
  register ak_uint64 v = 0;
  ak_uint64 *outptr = (ak_uint64 *)out;
  const ak_uint64 *inptr = (const ak_uint64 *)in;
#ifdef AK_HAVE_STDALIGN_H
  alignas(32)
#endif
  ak_uint64 t[2], temp[2] = { 0, 0 };
  ak_uint8 *tb = (ak_uint8 *)t;
  ssize_t i = 0,
          tail = ( ssize_t )( size&0xf ),
          blocks = ( ssize_t )( size >> 4 ),
          resource = (( blocks + (tail > 0)) << 1)/( encryptionKey->bsize >> 3 );
                                                                       /* общее количество блоков,
                                                                          подлежащее зашифрованию  */
 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;
 /* слишком короткие сообщения не умеем обрабатывать */
  if( !blocks && ( tail > 0 ))
    return ak_error_message( ak_error_wrong_length, __func__ ,
            "xtsmac mode unsupport short messages (length must be equal or more than block size)");

 /* проверка возможности обновления */
  if( ctx->flags&ak_aead_encrypted_data_bit )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                              "attemp to update previously closed xtsmac context");
 /* проверка ресурса ключа */
  if( encryptionKey->key.resource.value.counter < resource )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else encryptionKey->key.resource.value.counter -= resource;

 /* теперь основной цикл */
  switch( encryptionKey->bsize ) {
     case  8: /* шифр с длиной блока 64 бита */
       while( blocks > ( tail > 0 )) {
          ak_xtsmac_decrypt_step64( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;

     case 16: /* шифр с длиной блока 128 бит */
       while( blocks > ( tail > 0 )) {
          ak_xtsmac_decrypt_step128( inptr, outptr );
          ctx->pbitlen += 128;
          --blocks;
       }
       break;
  }

  if( tail ) { /* восстановливаем "скраденый" шифртекст */
    size_t adlen = 16 - tail;
    ak_uint64 *tpi = (ak_uint64 *)t, *tpo = (ak_uint64 *)temp,
              tgam[2] = { ctx->gamma[0], ctx->gamma[1] };

   /* сохраняем текущее значение гаммы и переходим к следующему */
    ak_xtsmac_next_gamma;
   /* расшифровываем последний полный блок */
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_decrypt_step64( inptr, outptr ); }
     else { ak_xtsmac_decrypt_step128( inptr, outptr ); }
    ctx->pbitlen += 128;

   /* формируем дополнительный полный блок */
    memcpy( tb, inptr, tail );
    memcpy( tb + tail, ((ak_uint8 *)outptr) - adlen, adlen );

   /* восстанавливаем значение гаммы и расшифровываем полученное */
    ctx->gamma[0] = tgam[0]; ctx->gamma[1] = tgam[1];
    if( encryptionKey->bsize == 8 ) { ak_xtsmac_decrypt_step64( tpi, tpo ); }
     else { ak_xtsmac_decrypt_step128( tpi, tpo ); }

   /* приводим гамму к ожидаемому виду */
    ak_xtsmac_next_gamma;
   /* размещаем по ячейкам */
    for( i = 0; i < tail; i++ ) ((ak_uint8* )outptr)[i] = ((ak_uint8 *)(outptr-2))[i];
    *(outptr-2) = temp[0];
    *(outptr-1) = temp[1];
    ak_aead_set_bit( ctx->flags, ak_aead_encrypted_data_bit );
    ctx->pbitlen += ( tail << 3 );

   /* заполняем память мусором */
    ak_ptr_wipe( tgam, sizeof( tgam ), &encryptionKey->key.generator );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим шифрования для блочного шифра с одновременным вычислением
    имитовставки. На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    для всех переданных на вход функции данных.

    Режим `xtsmac` должен использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если хотя бы один из указателей на ключ равен `NULL`, то возбуждается ошибка.

    \note Данный режим не позволяет обрабатывать сообщения, длина которых менее 16 октетов.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах, должен быть не менее 16 октетов;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее;
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно
           превышать 16 октетов; если значение icode_size, то возвращается запрашиваемое количество
           старших байт результата вычислений.

   @return Функция возвращает \ref ak_error_ok в случае успешного завершения.
   В противном случае, возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_encrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                   const size_t size, const ak_pointer iv, const size_t iv_size,
                                                       ak_pointer icode, const size_t icode_size )
{
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */

 /* проверки ключей */
  if(( encryptionKey == NULL ) || ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,"using null pointer to secret key" );
  if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
 /* подготавливаем память */
  memset( &ctx, 0, sizeof( struct xtsmac_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
  }

 /* потом зашифровываем данные */
  if(( error = ak_xtsmac_encryption_update( &ctx, encryptionKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
  }

 /* в конце - вырабатываем имитовставку */
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                         authenticationKey, icode, icode_size )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect finanlize of integrity code" );

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных. Требования к передаваемым параметрам
    аналогичны требованиям, предъявляемым к параметрам функции ak_bckey_encrypt_xtsmac().

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать 16 октетов;

    @return Функция возвращает \ref ak_error_ok, если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается код ошибки.             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_decrypt_xtsmac( ak_pointer encryptionKey, ak_pointer authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
  ak_uint8 icode2[16];
  int error = ak_error_ok;
  struct xtsmac_ctx ctx; /* контекст структуры, в которой хранятся промежуточные данные */

 /* проверки ключей */
  if(( encryptionKey == NULL ) || ( authenticationKey == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__ ,"using null pointer to secret key" );
  if( ((ak_bckey)encryptionKey)->bsize != ((ak_bckey)authenticationKey)->bsize )
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                    "different block sizes for given secret keys");
 /* подготавливаем память */
  memset( &ctx, 0, sizeof( struct xtsmac_ctx ));

 /* в начале обрабатываем ассоциированные данные */
  if(( error = ak_xtsmac_authentication_clean( &ctx, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__,
                                           "incorrect initialization of internal xtsmac context" );
  }
  if(( error = ak_xtsmac_authentication_update( &ctx, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ),&((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect hashing of associated data" );
  }

 /* потом зашифровываем данные */
  if(( error = ak_xtsmac_decryption_update( &ctx, encryptionKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)encryptionKey)->key.generator );
     return ak_error_message( error, __func__, "incorrect encryption of plain data" );
  }

 /* в конце - вырабатываем имитовставку */
  memset( icode2, 0, 16 );
  if(( error = ak_xtsmac_authentication_finalize( &ctx,
                                         authenticationKey, icode2, icode_size )) != ak_error_ok ) {
    ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
    return ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
  }

  ak_ptr_wipe( &ctx, sizeof( struct xtsmac_ctx ), &((ak_bckey)authenticationKey)->key.generator );
  if( ak_ptr_is_equal_with_log( icode2, icode, icode_size )) return ak_error_ok;

 return ak_error_not_equal_data;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_xts.c  */
/* ----------------------------------------------------------------------------------------------- */
