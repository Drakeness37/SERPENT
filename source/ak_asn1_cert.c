/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_cert.c                                                                            */
/*  - содержит реализацию функций, предназначенных для экспорта/импорта открытых ключей            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
                  /* Функции экспорта открытых ключей в запрос на сертификат */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует фрагмент asn1 дерева, содержащий параметры открытого ключа.
    \param vk контекст открытого ключа
    \return Функция возвращает указатель на tlv узел, содержащий сформированную структуру.
    В случае ошибки возвращается `NULL`.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_asn1_value( ak_verifykey vk )
{
  ak_oid ec = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, basn = NULL;
  size_t val64 = sizeof( ak_uint64 )*vk->wc->size;          /* количество октетов в одном вычете */
  ak_uint8 data[ 2*sizeof(ak_uint64)*ak_mpznmax_size ];    /* asn1 представление открытого ключа */
  ak_uint8 encode[ 4 + sizeof( data )];                             /* кодированная octet string */
  size_t sz = sizeof( encode );

  if(( error = ak_asn1_add_oid( asn = ak_asn1_new(), vk->oid->id[0] )) != ak_error_ok ) goto labex;
  if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, ak_asn1_new( ))) != ak_error_ok ) goto labex;
  if(( ec = ak_oid_find_by_data( vk->wc )) == NULL ) {
    ak_error_message( ak_error_wrong_oid, __func__,
                                 "public key has incorrect pointer to elliptic curve parameters" );
    goto labex;
  }
  ak_asn1_add_oid( asn->current->data.constructed, ec->id[0] );
  ak_asn1_add_oid( asn->current->data.constructed, vk->ctx.oid->id[0] );

  if(( basn = ak_asn1_new()) == NULL ) goto labex;
  if(( error = ak_asn1_add_asn1( basn, TSEQUENCE, asn )) != ak_error_ok ) {
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }

 /* кодируем открытый ключ => готовим octet string */
  memset( data, 0, sizeof( data ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, ( val64<<1 ), data, ak_false )) == NULL ){
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
 /* помещаем в нее данные */
  ak_wpoint_reduce( &vk->qpoint, vk->wc );
  ak_mpzn_to_little_endian( vk->qpoint.x, vk->wc->size, data, val64, ak_false );
  ak_mpzn_to_little_endian( vk->qpoint.y, vk->wc->size, data+val64, val64, ak_false );
  if(( error = ak_tlv_encode( os, encode, &sz )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of temporary tlv context" );
    if( os != NULL ) ak_tlv_delete( os );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
  bs.value = encode;
  bs.len = sz;
  bs.unused = 0;
  ak_asn1_add_bit_string( basn, &bs );
  if(( tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, basn )) == NULL ) {
    ak_asn1_delete( basn );
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect addition the bit sting with public key value" );
  }

  ak_tlv_delete( os );
 return  tlv;

 labex:
  if( asn != NULL ) ak_asn1_delete( asn );
  ak_error_message( ak_error_get_value(), __func__,
                                         "incorrect export of public key into request asn1 tree" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует asn1 дерево с запросом на сертификат открытого ключа.

    Выполняются следующие действия:

    - формируется tlv элемент, содержащий имя владельца, параметры алгоритма и значение ключа,
    - tlv элемент кодируется в der-последовательность,
    - вырабатывается подпись под der-последовательностью,
    - идентификатор алгоритма выработки подписи и значение подписи также помещаются в asn1 дерево.

   \param vk контекст открытого ключа
   \param sk контекст секретного ключа
   \param a уровень asn1 дерева, в который помещается запрос на сертификат.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_export_to_asn1_request( ak_verifykey vk, ak_signkey sk,
                                                                   ak_random generator, ak_asn1 a )
{
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );
  ak_tlv tlv = NULL, pkey = NULL;

  if( a == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 context" );
  if( !ak_ptr_is_equal( vk->number, sk->verifykey_number, sizeof( vk->number )))
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                     "secret key not correspondig to public key" );
  if( ak_signkey_get_tag_size( sk ) > sizeof( s ))
    ak_error_message( ak_error_wrong_length, __func__,
                                   "using digital signature algorithm with very large signature" );

 /* 1. Создаем последовательность, которая будет содержать данные запроса */
  if(( error = ak_asn1_add_asn1( a, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new())) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of first level sequence");
  }

 /* 2. Создаем tlv элемент, для которого, потом, будет вычисляться электронная подпись */
   tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new( ));
  /* добавляем ноль */
   ak_asn1_add_uint32( asn, 0 );
  /* копируем asn1 дерево с расширенным именем из структуры открытого ключа
     в asn1 дерево формируемого запроса */
   ak_asn1_add_tlv( asn, ak_tlv_duplicate_global_name( vk->name ));

  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_add_tlv( asn, pkey = ak_verifykey_export_to_asn1_value( vk ));
   if( pkey == NULL ) {
     if( tlv != NULL ) tlv = ak_tlv_delete( tlv );
     return ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect export of public key into tlv context" );
   }
  /* 0x00 это помещаемое в CONTEXT_SPECIFIC значение */
   ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00, ak_asn1_new( ));

  /* 3. Помещаем tlv элемент в основное дерево */
   ak_asn1_add_tlv( a->current->data.constructed, tlv );

  /* 4. Помещаем идентификатор алгоритма выработки подписи */
   ak_asn1_add_asn1( a->current->data.constructed, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new());
   ak_asn1_add_oid( asn, sk->key.oid->id[0] );

  /* 4. Помещаем bit-string со значением подписи */
   if(( error =  ak_tlv_encode( tlv, data, &size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect encoding of asn1 context");

   memset( s, 0, sizeof( s ));
   if(( error = ak_signkey_sign_ptr( sk, generator, data, size, s, sizeof( s ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect signing internal data" );
   bs.value = s;
   bs.len = ak_signkey_get_tag_size( sk );
   bs.unused = 0;
   if(( error = ak_asn1_add_bit_string( a->current->data.constructed, &bs )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию
    и сохраняет созданное дерево в файл, который называется "запросом на сертификат".

   \note Контекст секретного ключа `sk` должен соответствовать контексту открытого ключа `vk`.
   В противном случае нельзя будет проверить электронную подпись под открытым ключом, поскольку
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя создать запрос на сертификат ключа, который не поддерживает
   определенный библиотекой алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param vk Контекст открытого ключа
   \param sk Контекст секретного ключа, соответствующий открытому ключу
   \param generator Генератор псевдослучайных последовательностей, используемый для выработки
    электронной подписи под запросом на сертификат
   \param filename Указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  Размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format Формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_export_to_request( ak_verifykey vk, ak_signkey sk, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to public key context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );

 /* 1. При необходимости, формируем имя файла для экспорта открытого ключа
       Формируемое имя совпадает с номером ключа и однозначно зависит от его значения */
  if( size != 0 ) {
    memset( filename, 0, size );
    if( size < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                               "using small buffer to storing request file name" );
     else ak_snprintf( filename, size, "%s.csr",
                                   ak_ptr_to_hexstr( vk->number, sizeof( vk->number ), ak_false ));
  }

 /* 2. Создаем asn1 дерево */
  if(( error = ak_verifykey_export_to_asn1_request( vk, sk, generator,
                                                         asn = ak_asn1_new( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation af asn1 context" );
    goto labexit;
  }

 /* 3. Сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( asn,
                                filename, format, public_key_request_content )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect export asn1 context to file %s", filename );
    goto labexit;
  }

  labexit:
    if( asn != NULL ) asn = ak_asn1_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                 /* Функции импорта открытых ключей из запроса на сертификат */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значение открытого ключа из запроса на сертификат,
    разобранного в ASN.1 дерево, и создает контекст открытого ключа.

    Функция считывает oid алгоритма подписи и проверяет, что он соответствует ГОСТ Р 34.12-2012,
    потом функция считывает параметры эллиптической кривой и проверяет, что библиотека поддерживает
    данные параметры. В заключение функция считывает открытый ключ и проверяет,
    что он принадлежит кривой со считанными ранее параметрами.

    После выполнения всех проверок, функция создает (действие `create`) контекст открытого ключа,
    а также присваивает (действие `set_key`) ему считанное из asn1 дерева значение.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_request( ak_verifykey vkey, ak_asn1 asnkey )
{
  size_t size = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = asnkey, asnl1; /* копируем адрес */
  ak_uint32 val = 0, val64 = 0;

 /* проверяем, то первым элементом содержится ноль */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                          "the first element of root asn1 context be an integer" );
  ak_tlv_get_uint32( asn->current, &val );
  if( val != 0 ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
 /* второй элемент содержит имя владельца ключа.
    этот элемент должен быть позднее перенесен в контекст открытого ключа */
  ak_asn1_next( asn );

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the third element of root asn1 context must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                               "the first next level element must be a sequence" );
  asnl1 = asn->current->data.constructed;

 /* получаем алгоритм электронной подписи */
  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                          "the first element of child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
  if(( oid->engine != verify_function ) || ( oid->mode != algorithm ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* получаем параметры элиптической кривой */
  ak_asn1_next( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the second element of child asn1 context must be a sequence of object identifiers" );
  asnl1 = asnl1->current->data.constructed;

  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                     "the first element of last child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                            "import an unsupported object identifier %s for elliptic curve", ptr );
  if(( oid->engine != identifier ) || ( oid->mode != wcurve_params ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* создаем контекст */
  asnl1 = NULL;
  if(( error = ak_verifykey_create( vkey, (const ak_wcurve )oid->data )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of verify key context" );

 /* получаем значение открытого ключа */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a bit string" );
    goto lab1;
  }

 /* считали битовую строку, проверяем что это der-кодировка некоторого целого числа */
  if(( error = ak_asn1_decode( asnl1 = ak_asn1_new(),
                                                  bs.value, bs.len, ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect decoding a value of public key" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOCTET_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                                        "the public key must be an octet string" );
    goto lab1;
  }

 /* считываем строку и разбиваем ее на две половинки */
  val = ( ak_uint32 )vkey->wc->size;
  val64 = sizeof( ak_uint64 )*val;
  ak_tlv_get_octet_string( asnl1->current, &ptr, &size );
  if( size != 2*val64 ) {
    ak_error_message_fmt( error = ak_error_wrong_length, __func__ ,
        "the size of public key is equal to %u (must be %u octets)", (unsigned int)size, 2*val64 );
    goto lab1;
  }

 /* копируем данные и проверям, что точка действительно принадлежит кривой */
  ak_mpzn_set_little_endian( vkey->qpoint.x, val, ptr, val64, ak_false );
  ak_mpzn_set_little_endian( vkey->qpoint.y, val, ((ak_uint8*)ptr)+val64, val64, ak_false );
  ak_mpzn_set_ui( vkey->qpoint.z, val, 1 );
  if( ak_wpoint_is_ok( &vkey->qpoint, vkey->wc ) != ak_true ) {
    ak_error_message_fmt( error = ak_error_curve_point, __func__ ,
                                                  "the public key isn't on given elliptic curve" );
    goto lab1;
  }

 /* устанавливаем флаг и выходим */
  vkey->flags = ak_key_flag_set_key;

  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
 return ak_error_ok;

 lab1:
  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
  ak_verifykey_destroy( vkey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла запрос на получение сертификата. Запрос хранится в виде
    asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).

    \note Функция является конструктором контекста ak_verifykey.
    После считывания asn1 дерева  функция проверяет подпись под открытым ключом и,
    в случае успешной проверки, создает контекст `vkey` и инициирует его необходимыми значениями.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param filename имя файла
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_import_from_request( ak_verifykey vkey, const char *filename )
{
  size_t size = 0;
  ak_tlv tlv = NULL;
  struct bit_string bs;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  ak_asn1 root = NULL, asn = NULL, asnkey = NULL;

 /* стандартные проверки */
  if( vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    goto lab1;
  }

 /* первый узел позволит нам получить значение открытого ключа
    (мы считываем параметры эллиптической кривой, инициализируем контекст значением
    открытого ключа и проверяем, что ключ принадлежит указанной кривой ) */
  ak_asn1_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }
  if(( error = ak_verifykey_import_from_asn1_request( vkey,
                                     asnkey = asn->current->data.constructed )) != ak_error_ok ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of request" );
    goto lab1;
  }

 /* второй узел, в нашей терминологии, содержит идентификатор секретного ключа
    и бесполезен, поскольку вся информация об открытом ключе проверки подписи,
    эллиптической кривой и ее параметрах уже считана. остается только проверить подпись,
    расположенную в последнем, третьем узле запроса. */

 /* 1. Начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  memset( buffer, 0, size = sizeof( buffer ));
  ak_asn1_first( asn );
  if(( error = ak_tlv_encode( asn->current, buffer, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of asn1 context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 2. Теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3. Только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( vkey, buffer, size, bs.value ) != ak_true ) {
    ak_error_message( error = ak_error_get_value(), __func__, "digital signature isn't valid" );
    goto lab1;
  }

 /* 4. На основе считанных данных формируем номер ключа */
  if(( error = ak_verifykey_set_number( vkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation on public key number" );
    goto lab1;
  }

 /* 5. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_first( asn );
  asn = asn->current->data.constructed;
  ak_asn1_first( asn );
  ak_asn1_next( asn ); /* нужен второй узел */
  vkey->name = ak_asn1_exclude( asn );

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_verifykey_load_from_request( const char *filename )
{
  ak_pointer vkey = NULL;
  int error = ak_error_ok;

  if(( error = ak_verifykey_import_from_request( vkey = malloc( sizeof( struct verifykey )),
                                                                    filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                         "incorrect loading a public key from %s file", filename );
    if( vkey != NULL ) {
      ak_verifykey_destroy( vkey );
      free( vkey );
    }
  }

 return vkey;
}


/* ----------------------------------------------------------------------------------------------- */
                      /* Служебные функции для работы с сертификатами */
/* ----------------------------------------------------------------------------------------------- */
/*! Данный номер (serialNumber) зависит от номера секретного ключа, подписывающего открытый ключ и,
    тем самым, может принимать различные значения для каждого из подписывающих ключей.

    Серийный номер сертификата образуют младшие 32 байта результата хеширования
    последовательной конкатенации номеров открытого и секретного ключей.
    Для хеширования используется функция, определенная в контексте `секретного` ключа,
    т.е.  Стрибог512 для длинной подписи и Стрибог256 для короткой.

   \code
    result[0..31] = Hash( vk->number || sk->number )
   \endcode

    Вычисленное значение не помещается в контекст открытого ключа, а возвращается как
    большое целое число. Это позволяет использовать данную функцию как при экспорте,
    так и при импорте сертификатов открытых ключей (в момент разбора цепочек сертификации).

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param serialNumber переменная, в которую помещается серийный номер.
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_generate_certificate_number( ak_verifykey vk,
                                                          ak_signkey sk, ak_mpzn256 serialNumber )
{
  ak_uint8 result[64];

 /* используем для хеширования контекст секретного ключа */
  if( ak_hash_get_tag_size( &sk->ctx ) > sizeof( result ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                      "using secret key with huge signature tag" );
  memset( result, 0, sizeof( result ));
  ak_hash_clean( &sk->ctx );
  ak_hash_update( &sk->ctx, vk->number, sizeof( vk->number ));
  ak_hash_finalize( &sk->ctx, sk->key.number, sizeof( sk->key.number ), result, sizeof( result ));
  ak_mpzn_set_little_endian( serialNumber, ak_mpzn256_size, result, 32, ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции экспорта открытых ключей в сертификат */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание tlv узла, содержащего структуру TBSCertificate версии 3
    в соответствии с Р 1323565.1.023-2018.

   Структура `tbsCertificate` определяется следующим образом

   \code
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  Extensions OPTIONAL
                             -- If present, version MUST be v3 --  }
   \endcode

   Перечень добавляемых расширений определяется значениями аргумента `opts`.

   \param subject_vkey контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_vkey контект ключа проверки подписи, содержащий параметры центра сертификации
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_tbs( ak_verifykey subject_vkey, ak_signkey issuer_skey,
                                               ak_verifykey issuer_vkey, ak_certificate_opts opts )
{
  ak_mpzn256 serialNumber;
  ak_tlv tbs = NULL, tlv = NULL;
  ak_asn1 asn = NULL, tbasn = NULL;

  if(( tbs = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
   else tbasn = tbs->data.constructed;

 /* теперь создаем дерево сертификата в соответствии с Р 1323565.1.023-2018
    version: начинаем с размещения версии сертификата, т.е. ветки следующего вида
     ┐
     ├[0]┐
     │   └INTEGER 2 (величина 2 является максимально возможным значением ) */

  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x00, asn = ak_asn1_new( ));
  if( asn != NULL ) ak_asn1_add_uint32( asn, 2 );
    else {
      ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect creation of certificate version context");
      goto labex;
    }

 /* serialNumber: вырабатываем и добавляем номер сертификата */
  ak_verifykey_generate_certificate_number( subject_vkey, issuer_skey, serialNumber );
  ak_asn1_add_mpzn( tbasn, TINTEGER, serialNumber, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_add_tlv( tbasn, tlv = ak_tlv_new_sequence( ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( tlv->data.constructed, issuer_skey->key.oid->id[0] );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( issuer_vkey->name ));

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_add_validity( tbasn, issuer_skey->key.resource.time.not_before,
                                                        issuer_skey->key.resource.time.not_after );
 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( subject_vkey->name ));

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_add_tlv( tbasn, tlv = ak_verifykey_export_to_asn1_value( subject_vkey ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }

 /* теперь мы принимаем решение - сертификат самоподписанный или нет
    выполняется проверка на совпадение subjectKeyIdentifier (номера открытого ключа)  */
  if( ak_ptr_is_equal( subject_vkey->number, issuer_vkey->number, 32 )) {
    opts->ca.is_present = ak_true;
    opts->ca.value = ak_true;
    if( !(opts->key_usage.bits&bit_keyCertSign )) opts->key_usage.bits ^= bit_keyCertSign;

   /* для самоподписанных сертификатов расширение authority_key_identifier будет добавляться
      только по запросу пользователя (т.е. в случае установки флага)
      для прочих сертификатов - расширение добавляется всегда */
  }
   else opts->authority_key_identifier.is_present = ak_true;

 /* далее мы реализуем возможности сертификатов третьей версии, а именно
    вставляем перечень расширений
    0x03 это помещаемое в CONTEXT_SPECIFIC значение */
  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x03, asn = ak_asn1_new( ));
  if( asn == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                      "incorrect creation of certificate extensions asn1 context");
    goto labex;
  }
  ak_asn1_add_tlv( asn, ak_tlv_new_sequence( ));
  asn = asn->current->data.constructed;

 /* 1. В обязательном порядке добавляем номер открытого ключа */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_subject_key_identifier( subject_vkey->number, 32 ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
    goto labex;
  }

 /* 2. Если определено расширение BasicConstraints, то добавляем его
      (расширение может добавляться не только в самоподписаные сертификаты) */
  if( opts->ca.is_present ) {
    ak_asn1_add_tlv( asn,
                tlv = ak_tlv_new_basic_constraints( opts->ca.value , opts->ca.pathlenConstraint ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 3. Если определены флаги keyUsage, то мы добавляем соответствующее расширение */
  if( opts->key_usage.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_key_usage( opts->key_usage.bits ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 4. Добавляем имена для поиска ключа проверки подписи (Authority Key Identifier) */
  if( opts->authority_key_identifier.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_authority_key_identifier( issuer_skey,
                                       issuer_vkey, opts->authority_key_identifier.include_name ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                    "incorrect generation of Authority Key Identifier extension" );
      goto labex;
    }
  }

 return tbs;

  labex: if( tbs != NULL ) tbs = ak_tlv_delete( tbs );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает asn1 дерево, содержащее сертификат открытого ключа.

   \param subject_vkey контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_vkey контект ключа проверки подписи, содержащий параметры центра сертификации
   \param generator геератор случайных последовательностей, используемый для подписи сертификата
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_asn1 ak_verifykey_export_to_asn1_certificate( ak_verifykey subject_vkey,
  ak_signkey issuer_skey, ak_verifykey issuer_vkey, ak_random generator, ak_certificate_opts opts )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* создаем контейнер для сертификата */
  if(( error = ak_asn1_add_tlv( certificate = ak_asn1_new(),
                                         tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* создаем поле tbsCertificate */
  if(( tbs = ak_verifykey_export_to_tbs( subject_vkey, issuer_skey, issuer_vkey, opts )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of tbsCertificate element" );
    goto labex;
  }

 /* вставляем в основное дерево созданный элемент */
  ak_asn1_add_tlv( tlv->data.constructed, tbs );
 /* добавляем информацию о алгоритме подписи */
  ak_asn1_add_tlv( tlv->data.constructed, ta = ak_tlv_new_sequence( ));
  if( ta == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( ta->data.constructed, issuer_skey->key.oid->id[0] );

 /* вырабатываем подпись */
  len = sizeof( encode );
  if(( error = ak_tlv_encode( tbs, encode, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of tbsCertificate element" );
    goto labex;
  }
  if(( error = ak_signkey_sign_ptr( issuer_skey, generator, encode,
                                                      len, out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of digital signature" );
    goto labex;
  }

 /* добавляем подпись в основное дерево */
  bs.value = out;
  bs.len = ak_signkey_get_tag_size( issuer_skey );
  bs.unused = 0;
  if(( error = ak_asn1_add_bit_string( tlv->data.constructed, &bs )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );
    goto labex;
  }
 return certificate;

  labex: if( certificate != NULL ) certificate = ak_asn1_delete( certificate );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл (сертификат открытого ключа)
    в заданном пользователем формате.

   \param subject_vkey контекст открытого ключа, который помещается в сертификат; контекст должен
   содержать расширенное имя лица (subject), владеющего открытым ключом.
   \param issuer_skey контекст секретного ключа, с помощью которого подписывается создаваемый сертификат;
   \param issuer_vkey контекст открытого ключа, соответствующий секретному ключу подписи;
   данный контекст используется для получения расширенного имени лица,
   подписывающего сертификат (issuer), а также для проверки разрешений на использование сертификата.
   \param generator геератор слечайных последовательностей, используемый для подписи сертификата.
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные, допутимые значения
   \ref asn1_der_format или \ref asn1_pem_format.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_export_to_certificate( ak_verifykey subject_vkey,
          ak_signkey issuer_skey, ak_verifykey issuer_vkey, ak_random generator,
              ak_certificate_opts opts, char *filename, const size_t size, export_format_t format )
{
  ak_mpzn256 serialNumber;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
   "cer",
   "crt"
  };

 /* необходимые проверки */
  if( subject_vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                            "using null pointer to subject's public key context" );
  if( issuer_skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's secret key context" );
  if( issuer_vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's public key context" );

 /* проверяем, что секретный ключ соответствует открытому */
  if( memcmp( issuer_skey->verifykey_number, issuer_vkey->number, 32 ) != 0 )
    return ak_error_message( ak_error_not_equal_data, __func__,
                           "the issuer's secret key does not correspond to the given public key" );

  /* вырабатываем asn1 дерево */
  if(( certificate = ak_verifykey_export_to_asn1_certificate(
                               subject_vkey, issuer_skey, issuer_vkey, generator, opts )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect creation of asn1 context for certificate" );
 /* формируем имя файла для хранения ключа
    (данное имя в точности совпадает с номером ключа) */
  if( size ) {
    if( size < ( 5 + 2*sizeof( subject_vkey->number )) ) {
      ak_error_message( error = ak_error_out_of_memory, __func__,
                                              "insufficent buffer size for certificate filename" );
      goto labex;
    }
    memset( filename, 0, size );
    ak_verifykey_generate_certificate_number( subject_vkey, issuer_skey, serialNumber );
    ak_snprintf( filename, size, "%s.%s",
          ak_mpzn_to_hexstr( serialNumber, ak_mpzn256_size ), file_extensions[format] );
  }

 /* сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( certificate, filename,
                                        format, public_key_certificate_content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );

  labex: if( certificate != NULL ) certificate = ak_asn1_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции импорта открытых ключей из сертификата */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_cert.c  */
/* ----------------------------------------------------------------------------------------------- */
