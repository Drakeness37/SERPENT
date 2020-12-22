/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Portions Copyright (c) 1996-1999 by Internet Software Consortium.                              */
/*  Portions Copyright (c) 1995 by International Business Machines, Inc.                           */
/*                                                                                                 */
/*  Файл ak_base64.с                                                                               */
/*  - содержит реализацию функций для кодирования/декодирования данных в формате BASE64            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Encoding table as described in RFC1113 */
 static const char base64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ----------------------------------------------------------------------------------------------- */
/*! \param in  указатель на кодируемые данные,
    \param out указатель на данные, куда помещается результат
    \param len количество кодируемых октетов (от одного до трех)                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_base64_encodeblock( ak_uint8 *in, ak_uint8 *out, int len )
{
    out[0] = (ak_uint8) base64[ (int)(in[0] >> 2) ];
    out[1] = (ak_uint8) base64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
    out[2] = (ak_uint8) (len > 1 ? base64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
    out[3] = (ak_uint8) (len > 2 ? base64[ (int)(in[2] & 0x3f) ] : '=');
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция пытается считать данные из файла в буффер, на который указывает `buf`.
    Данные в файле должны быть сохранены в формате base64. Все строки файлов,
    содержащие последовательность символов "-----",
    а также ограничители '#', ':', игнорируются.

    Пробелы игнорируются.

    В оставшихся строках символы, не входящие в base64, вызывают ошибку декодирования.

 \note Функция экспортируется.
 \param buf указатель на массив, в который будут считаны данные;
 память может быть выделена заранее, если память не выделена, то указатель должен принимать
 значение NULL.
 \param size размер выделенной заранее памяти в байтах;
 в случае выделения новой памяти, в переменную `size` помещается размер выделенной памяти.
 \param filename файл, из которого будет производиться чтение.

 \return Функция возвращает указатель на буффер, в который помещены данные.
 Если произошла ошибка, то функция возвращает NULL; код ошибки может быть получен с помощью
 вызова функции ak_error_get_value().                                                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_ptr_load_from_base64_file( ak_pointer buf, size_t *size, const char *filename )
{
  struct file sfp;
  ak_uint64 idx = 0;
  size_t ptrlen = 0, len = 0;
  ak_uint8 *ptr = NULL;
  char ch, localbuffer[1024];
  int error = ak_error_ok, off = 0;

 /* открываемся */
  if(( error = ak_file_open_to_read( &sfp, filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "wrong opening the %s", filename );
    return NULL;
  }

  /* надо бы определиться с размером буффера:
     величины 1 + sfp.size*3/4 должно хватить, даже без лишних символов. */
  if( sfp.size < 5 ) {
    ak_error_message( ak_error_zero_length, __func__, "loading from file with zero length" );
    ak_file_close( &sfp );
    return NULL;
  } else ptrlen = 1 + (( 3*sfp.size ) >> 2);

 /* проверяем наличие доступной памяти */
  if(( buf == NULL ) || ( ptrlen > *size )) {
    if(( ptr = malloc( ptrlen )) == NULL ) {
      ak_error_message( error = ak_error_out_of_memory, __func__, "incorrect memory allocation" );
      goto  exlab;
    }
  } else { ptr = buf; }

 /* нарезаем входные данные на строки длиной не более чем 1022 символа */
  memset( ptr, 0, ptrlen );
  memset( localbuffer, 0, sizeof( localbuffer ));
  for( idx = 0; idx < (size_t) sfp.size; idx++ ) {
     if( ak_file_read( &sfp, &ch, 1 ) != 1 ) {
       ak_error_message_fmt( error = ak_error_read_data, __func__ ,
                                                               "unexpected end of %s", filename );
       goto exlab;
     }
     if( off > 1022 ) {
       ak_error_message_fmt( error = ak_error_read_data, __func__ ,
                                          "%s has a line with more than 1022 symbols", filename );
       goto exlab;
     }
    if( ch == '\n' ) {
      int state = 0;
      char *pos = 0;
      size_t i = 0, slen = strlen( localbuffer );

     /* обрабатываем конец строки для файлов, созданных в Windows */
      if((slen > 0) && (localbuffer[slen-1] == 0x0d )) { localbuffer[slen-1] = 0; slen--; }

     /* проверяем корректность строки с данными */
      if(( slen != 0 ) &&              /* строка не пустая */
         ( slen%4 ==0 ) &&             /* длина строки кратна четырем */
         ( strchr( localbuffer, '#' ) == 0 ) &&        /* строка не содержит символ # */
         ( strchr( localbuffer, ':' ) == 0 ) &&        /* строка не содержит символ : */
         ( strstr( localbuffer, "-----" ) == NULL )) { /* строка не содержит ----- */

        /* теперь последовательно декодируем одну строку */
         while(( ch = localbuffer[i++]) != 0 ) {
           if( ch == ' ' ) continue; /* пробелы пропускаем */
           if( ch == '=' ) break;    /* достигли конца данных */
           if(( pos = strchr( base64, ch )) == NULL ) { /* встречен некорректный символ */
             ak_error_message_fmt( error = ak_error_undefined_value, __func__ ,
                                                    "%s contains an incorrect symbol", filename );
             goto exlab;
           }
           if( len + 1 >= ptrlen ) { /* достаточно места для хранения данных */
             ak_error_message( error = ak_error_wrong_index, __func__ ,
                                                                   "current index is too large" );
             goto exlab;
           }
           switch( state ) {
             case 0:
               ptr[len] = (pos - base64) << 2;
               state = 1;
             break;

             case 1:
               ptr[len] |= (pos - base64) >> 4;
               ptr[len+1] = ((pos - base64) & 0x0f) << 4;
               len++;
               state = 2;
             break;

             case 2:
               ptr[len] |= (pos - base64) >> 2;
               ptr[len+1] = ((pos - base64) & 0x03) << 6;
               len++;
               state = 3;
             break;

             case 3:
               ptr[len] |= (pos - base64);
               len++;
               state = 0;
             break;
             default: break;
           }
         }

        /* обработка конца данных */
         if( ch == '=' ) {
           if(( state == 0 ) || ( state == 1 )) {
             ak_error_message( error = ak_error_wrong_length, __func__ ,
                                                     "incorrect last symbol(s) of encoded data" );
             goto exlab;
           }
         }

      } /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, 1024 );
    } else localbuffer[off++] = ch;
  }

 /* получили нулевой вектор => ошибка */
  if( len == 0 ) ak_error_message_fmt( error = ak_error_zero_length, __func__,
                                       "%s not contain a correct base64 encoded data", filename );
 exlab:
  *size = len;
  ak_file_close( &sfp );
  if( error != ak_error_ok ) {
    if( ptr != NULL ) free(ptr);
    ptr = NULL;
  }
 return ptr;
}

/* ----------------------------------------------------------------------------------------------- */
/* ak_base64.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
