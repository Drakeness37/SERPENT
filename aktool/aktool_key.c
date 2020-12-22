/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_certificate( void );
 int aktool_key_new_keypair( bool_t , bool_t );
 int aktool_key_new_blom( void );
 int aktool_key_input_name( ak_verifykey );
 int aktool_key_print_disclaimer( void );
 int aktool_key_load_user_password_twice( void );
 int aktool_key_load_user_password( char * , const size_t );

/* ----------------------------------------------------------------------------------------------- */
#if defined(__unix__) || defined(__APPLE__)
  #define aktool_default_generator "dev-random"
#else
  #ifdef AK_HAVE_WINDOWS_H
    #define aktool_default_generator "winrtl"
  #else
    #define aktool_default_generator "lcg"
  #endif
#endif

#define aktool_magic_number (113)

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   ak_oid algorithm;
   ak_oid oid_of_generator;
   char *name_of_file_for_generator;
   export_format_t format;
   ak_oid curve;
   size_t days;
   ak_uint32 field, size;
   int verbose;
   struct certificate_opts opts;
   char password[aktool_password_max_length];
   size_t lenpass, lenuser;
   bool_t hexload;
   char keylabel[256];
   char user_id[256]; /* идентификатор пользователя ключа */
   char target[32]; /* целевой алгоритм для создаваемого ключа */

   char os_file[FILENAME_MAX];   /* сохраняем секретный ключ */
   char op_file[FILENAME_MAX];    /* сохраняем открытый ключ */
   char req_file[FILENAME_MAX];      /* читаем открытый ключ */
   char key_file[FILENAME_MAX];     /* читаем секретный ключ */
   char pubkey_file[FILENAME_MAX];   /* читаем открытый ключ */
 } ki;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, tchar *argv[] )
{
  char tmp[4];
  size_t i = 0;
  ak_uint32 value = 0;
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_cert } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "cert",                0, NULL,  'c' },
     { "new",                 0, NULL,  'n' },
     { "output-secret-key",   1, NULL,  'o' },
     { "to",                  1, NULL,  250 },
     { "hexpass",             1, NULL,  249 },
     { "password",            1, NULL,  248 },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },

     { "pubkey",              1, NULL,  208 },
     { "label",               1, NULL,  207 },
     { "random-file",         1, NULL,  206 },
     { "random",              1, NULL,  205 },
     { "req",                 1, NULL,  204 },
     { "key",                 1, NULL,  203 },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },

    /* флаги использования открытого ключа */
     { "digital-signature",   0, NULL,  190 },
     { "content-commitment",  0, NULL,  191 },
     { "key-encipherment",    0, NULL,  192 },
     { "data-encipherment",   0, NULL,  193 },
     { "key-agreement",       0, NULL,  194 },
     { "key-cert-sign",       0, NULL,  195 },
     { "crl-sign",            0, NULL,  196 },
     { "ca",                  1, NULL,  197 },
     { "pathlen",             1, NULL,  198 },
     { "authority-keyid",     0, NULL,  199 },
     { "authority-name",      0, NULL,  200 },

   /* флаги для генерации ключей схемы Блома */
     { "hexload",             0, NULL,  179 },
     { "field",               1, NULL,  180 },
     { "size",                1, NULL,  181 },
     { "id",                  1, NULL,  182 },
     { "hexid",               1, NULL,  183 },
     { "target",              1, NULL,  184 },

   /* это стандартые для всех программ опции */
     { "openssl-style",       0, NULL,   5  },
     { "audit",               1, NULL,   4  },
     { "dont-use-colors",     0, NULL,   3  },
     { "audit-file",          1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  },
  };

 /* инициализируем множество параметров по-умолчанию */
  memset( &ki, 0, sizeof( struct key_info ));
  ki.algorithm = NULL;
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );
  ki.name_of_file_for_generator = NULL;
  ki.format = asn1_der_format;
  ki.curve = ak_oid_find_by_name( "id-tc26-gost-3410-2012-256-paramSetA" );
  ki.days = 365;
 /* параметры секретного ключа для схемы Блома */
  ki.field = ak_galois256_size;
  ki.size = 512;
  ki.verbose = ak_true;
  ki.hexload = ak_false;
 /*  далее ki.opts состоит из одних нулей */

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:nco:", long_options, NULL );
       switch( next_option )
      {
        case  1  :   return aktool_key_help();
        case  2  : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
        case  3  : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_error_set_color_output( ak_false );
                     ak_libakrypt_set_option( "use_color_output", 0 );
                     break;
        case  4  : /* устанавливаем уровень аудита */
                     aktool_log_level = atoi( optarg );
                     break;
        case  5  : /* переходим к стилю openssl */
                     aktool_openssl_compability = ak_true;
                     break;

      /* управляющие команды */
        case 'n' :  work = do_new;
                    break;
        case 'c' :  work = do_cert;
                    break;

     /* устанавливаем имя криптографического алгоритма*/
        case 'a' :  if(( ki.algorithm = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(
                        _("using unsupported name or identifier \"%s\" for elliptic curve"),
                                                                                          optarg );
                      printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                    }
                    if( ki.algorithm->mode != algorithm ) {
                      aktool_error(_("%s is not valid identifier for algorithm"), optarg );
                      printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                      return EXIT_FAILURE;
                    }
                    break;

     /* устанавливаем имя генератора ключевой информации */
        case 205:   if(( ki.oid_of_generator = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(
                        _("using unsupported name or identifier \"%s\" for random generator"),
                                                                                          optarg );
                      printf(
                     _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                    }
                    if(( ki.oid_of_generator->engine != random_generator ) ||
                                                     ( ki.oid_of_generator->mode != algorithm )) {
                      aktool_error(_("%s is not valid identifier for random generator"), optarg );
                      printf(
                     _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                      return EXIT_FAILURE;
                    }
                    break;

     /* устанавливаем имя файла для генератора ключевой информации */
        case 206:   ki.name_of_file_for_generator = optarg;
                    break;

     /* запоминаем упользовательское описание ключа */
        case 207:   memcpy( ki.keylabel, optarg,
                                              ak_min( strlen( optarg ), sizeof( ki.keylabel )-1 ));
                    break;

     /* устанавливаем имена файлов (в полном, развернутом виде) */
        case 'o': /* --o, --output-secret-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
                  #else
                    realpath( optarg , ki.os_file );
                  #endif
                    break;

        case 202: /* --op, --output-public-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
                  #else
                    realpath( optarg , ki.op_file );
                  #endif
                    break;

        case 203: /* --key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

        case 204: /* --req */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.req_file, NULL );
                  #else
                    realpath( optarg , ki.req_file );
                  #endif
                    break;

        case 208: /* --pubkey */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                    realpath( optarg , ki.pubkey_file );
                  #endif
                    break;

     /* интервал действия ключа */
        case 246: /* --days */
                    ki.days = atoi( optarg );
                    if( !ki.days ) ki.days = 365;
                    break;

     /* проверяем идентификатор кривой */
        case 247: /* --curve  */
                   if(( ki.curve = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for elliptic curve"),
                                                                                          optarg );
                     printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if(( ki.curve->engine != identifier ) || ( ki.curve->mode != wcurve_params )) {
                      aktool_error(_("%s is not valid identifier for elliptic curve"), optarg );
                      printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                       return EXIT_FAILURE;
                     }
                   break;

     /* передача пароля через командную строку */
        case 248: /* --password */
                   memset( ki.password, 0, sizeof( ki.password ));
                   strncpy( ki.password, optarg, sizeof( ki.password ) -1 );
                   ki.lenpass = strlen( ki.password );
                   break;

        case 249: /* --hexpass */
                   memset( ki.password, 0, sizeof( ki.password ));
                   if( ak_hexstr_to_ptr( optarg, ki.password,
                                              sizeof( ki.password ), ak_false ) == ak_error_ok ) {
                     ki.lenpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                            sizeof( ki.password ));
                   }
                    else ki.lenpass = 0;
                   break;

     /* определяем формат выходных данных */
        case 250: /* --to */
                   memset( tmp, 0, sizeof( tmp ));
                   strncpy( tmp, optarg, 3 );
                   for( i = 0; i < sizeof( tmp )-1; i ++ ) tmp[i] = toupper( tmp[i] );

                   ki.format = -1;
                   if( strncmp( tmp, "DER", 3 ) == 0 )
                     ki.format = asn1_der_format;
                    else
                      if( strncmp( tmp, "PEM", 3 ) == 0 )
                        ki.format = asn1_pem_format;
                       else
                         if( strncmp( tmp, "CER", 3 ) == 0 )
                           ki.format = aktool_magic_number;
                          else {
                             aktool_error(_("%s is not valid format of output data"), optarg );
                             return EXIT_FAILURE;
                          }
                   break;

     /* устанавливаем биты для keyUsage и другие параметры сертификата */
        case 190:  ki.opts.key_usage.bits ^= bit_digitalSignature;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 191:  ki.opts.key_usage.bits ^= bit_contentCommitment;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 192:  ki.opts.key_usage.bits ^= bit_keyEncipherment;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 193:  ki.opts.key_usage.bits ^= bit_dataEncipherment;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 194:  ki.opts.key_usage.bits ^= bit_keyAgreement;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 195:  ki.opts.key_usage.bits ^= bit_keyCertSign;
                   ki.opts.key_usage.is_present = ak_true;
                   break;
        case 196:  ki.opts.key_usage.bits ^= bit_cRLSign;
                   ki.opts.key_usage.is_present = ak_true;
                   break;

        case 197: /* --ca */
                   if( strncmp( optarg, "true", 4 ) == 0 )
                     ki.opts.ca.is_present = ki.opts.ca.value = ak_true;
                    else
                     if( strncmp( optarg, "false", 5 ) == 0 ) {
                       ki.opts.ca.is_present = ak_true;
                       ki.opts.ca.value = ak_false;
                     }
                      else {
                             aktool_error(
                              _("%s is not valid value of certificate authority option"), optarg );
                             return EXIT_FAILURE;
                           }
                   break;

        case 198: /* --pathlen */
                   if(( value = atoi( optarg )) == 0 ) {
                     aktool_error(_("the value of \"pathlenConstraints\" must be positive integer"));
                     return EXIT_FAILURE;
                   }
                   ki.opts.ca.is_present = ki.opts.ca.value = ak_true;
                   ki.opts.ca.pathlenConstraint = ak_min( 100, value );
                   break;

        case 199:  ki.opts.authority_key_identifier.is_present = ak_true;
                   break;
        case 200:  ki.opts.authority_key_identifier.is_present = ak_true;
                   ki.opts.authority_key_identifier.include_name = ak_true;
                   break;

        case 179: /* --hexload */
                   ki.hexload = ak_true;
                   break;

        case 180: /* --field */
                   ki.field = atoi( optarg );
                   if(( ki.field != ak_galois256_size ) && ( ki.field != ak_galois512_size )) {
                     if( ki.field == 256 ) ki.field >>= 3;
                       else
                        if( ki.field == 512 ) ki.field >>= 3;
                          else {
                            aktool_error(_("incorrect value of field size,"
                                           " use \"--field 256\" or \"--field 512\" option"));
                            return EXIT_FAILURE;
                          }
                   }
                   break;

        case 181: /* --size */
                   if(( ki.size = atoi( optarg )) == 0 ) ki.size = 512;
                   if( ki.size > 4096 ) ki.size = 4096; /* ограничение по реализации */
                   break;

        case 182: /* --id */
                   memset( ki.user_id, 0, sizeof( ki.user_id ));
                   strncpy( ki.user_id, optarg, sizeof( ki.user_id ) -1 );
                   ki.lenuser = strlen( ki.user_id );
                   break;

        case 183: /* --hexid */
                   memset( ki.user_id, 0, sizeof( ki.user_id ));
                   if( ak_hexstr_to_ptr( optarg, ki.user_id,
                                              sizeof( ki.user_id ), ak_false ) == ak_error_ok ) {
                      ki.lenuser = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                             sizeof( ki.user_id ));
                   }
                    else ki.lenuser = 0;
                   break;

        case 184: /* --target */
                   memset( ki.target, 0, sizeof( ki.target ));
                   strncpy( ki.target, optarg, sizeof( ki.target ) -1 );
                   break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_key_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;
   ak_libakrypt_set_password_read_function( aktool_key_load_user_password );

 /* теперь вызов соответствующей функции */
   switch( work ) {
     case do_new:
       exit_status = aktool_key_new();
       break;

     case do_cert:
       exit_status = aktool_key_certificate();
       break;

     default:
       exit_status = EXIT_FAILURE;
   }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
  /* проверяем входые данне */
   if( ki.algorithm == NULL ) {
     aktool_error(
          _("use -a (--algorithm) option and set the cryptographic algorithm name or identifier"));
     return EXIT_FAILURE;
   }

  /* запускаем процедуру генерации ключа или ключевой пары */
   switch( ki.algorithm->engine ) {
    case block_cipher:
    case hmac_function:
      return aktool_key_new_keypair( ak_true, ak_false );

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair( ak_true, ak_true );

    case blom_master:
    case blom_abonent:
    case blom_pairwise:
      return aktool_key_new_blom();

   default:
      aktool_error(_("the string %s (%s) is an identifier of %s wich does not use a cryptographic key"),
                                       ki.algorithm->name[0], ki.algorithm->id[0],
                                             ak_libakrypt_get_engine_name( ki.algorithm->engine ));
      return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Эта функция используется при импорте ключа (однократное чтение пароля) */
 int aktool_key_load_user_password( char *password, const size_t pass_size )
{
  char *buffer = NULL;
  int error = ak_error_ok, bufsize = 1 + ( pass_size << 1 );

  if(( buffer = malloc( bufsize )) == NULL ) {
    aktool_error(_("out of memory"));
    return ak_error_out_of_memory;
  }

  fprintf( stdout, _("password"));
   if( ki.hexload ) fprintf( stdout, _(" [as hexademal string]"));
  fprintf( stdout, ": "); fflush( stdout );
  error = ak_password_read( buffer, bufsize );
  fprintf( stdout, "\n" );

  memset( password, 0, pass_size );
  if( ki.hexload ) {
    error = ak_hexstr_to_ptr( buffer, password, pass_size, ak_false );
  }
   else memcpy( password, buffer, ak_min( pass_size - 1, strlen( buffer )));

  if( buffer ) free( buffer );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Эта функция используется перед экспортом ключа */
 int aktool_key_load_user_password_twice( void )
{
  char *buffer = NULL;
  int error = ak_error_ok, bufsize = 1 + ( sizeof( ki.password ) << 1 );

  if(( buffer = malloc( bufsize )) == NULL ) {
    aktool_error(_("out of memory"));
    return ak_error_out_of_memory;
  }

 /* считываем первое значение */
  fprintf( stdout, _("password"));
   if( ki.hexload ) fprintf( stdout, _(" [as hexademal string]"));
  fprintf( stdout, ": "); fflush( stdout );
  error = ak_password_read( buffer, bufsize );
  fprintf( stdout, "\n" );

  memset( ki.password, 0, sizeof( ki.password ));
  if( ki.hexload ) {
    error = ak_hexstr_to_ptr( buffer, ki.password, sizeof( ki.password ), ak_false );
    ki.lenpass = strlen( buffer )%2 + ( strlen( buffer ) >> 1 );
  }
   else memcpy( ki.password, buffer, ak_min( sizeof( ki.password ) - 1, strlen( buffer )));

 /* теперь считываем пароль второй раз и проверяем совпадение */
  printf(_("retype password"));
   if( ki.hexload) fprintf( stdout, _(" [as hexademal string]"));
  fprintf( stdout, ": "); fflush( stdout );

  if( ak_password_read( buffer, bufsize ) != ak_error_ok ) {
    aktool_error(_("incorrect password"));
    error = ak_error_read_data;
    goto labex;
  } else printf("\n");

  if( ki.hexload ) {
    char password2[aktool_password_max_length];
      error = ak_hexstr_to_ptr( buffer, password2, sizeof( password2 ), ak_false );
      if( !ak_ptr_is_equal( ki.password, password2, ki.lenpass )) {
        aktool_error(_("the passwords don't match"));
        error = ak_error_not_equal_data;
        goto labex;
      }
  }
   else {
    if(( strlen( ki.password ) != strlen( buffer )) ||
       ( !ak_ptr_is_equal( ki.password, buffer, strlen( ki.password )))) {
      aktool_error(_("the passwords don't match"));
      error = ak_error_not_equal_data;
      goto labex;
    }
    ki.lenpass = strlen( ki.password );
  }
  labex: if( buffer ) free( buffer );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_new_blom_master( void )
{
  struct blomkey master;
  int exitcode = EXIT_FAILURE;
  ak_pointer generator = NULL;

 /* формируем генератор случайных чисел */
  if( ki.name_of_file_for_generator != NULL ) {
    if( ak_random_create_file( generator = malloc( sizeof( struct random )),
                                                ki.name_of_file_for_generator ) != ak_error_ok ) {
      if( generator ) free( generator );
      return exitcode;
    }
  }
   else
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return exitcode;

  if( ki.verbose ) {
    printf(_("      field: GF(2^%u)\n"), ki.field << 3 );
    printf(_("matrix size: %ux%u\n generation: "), ki.size, ki.size );
    fflush( stdout );
  }

 /* вырабатываем ключ заданного размера */
  if( ak_blomkey_create_matrix( &master, ki.size, ki.field, generator ) != ak_error_ok ) {
    aktool_error(_("incorrect master key generation"));
    goto labex;
  }
  if( ki.verbose ) { printf(_("Ok\n")); }

 /* запрашиваем пароль */
  if( aktool_key_load_user_password_twice() != ak_error_ok ) goto labex1;
 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &master,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s"), ki.os_file );
     else {
       printf(_("secret key stored in %s\n"), ki.os_file );
       exitcode = EXIT_SUCCESS;
     }

 labex1:
  ak_blomkey_destroy( &master );

 labex:
  if( ki.name_of_file_for_generator != NULL ) {
    ak_random_destroy( generator );
    free( generator );
  }
   else ak_oid_delete_object( ki.oid_of_generator, generator );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_new_blom_abonent( void )
{
  int exitcode = EXIT_FAILURE;
  struct blomkey master, abonent;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or abonent's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with master key is undefined, use \"--key\" option" ));
    return exitcode;
  }
 /* запрашиваем пароль для доступа к мастер ключу (однократно, без дублирования) */
  if( ki.verbose ) printf(_("master key: %s\n"), ki.key_file );
  if( ki.lenpass == 0 ) {
    if( aktool_key_load_user_password( ki.password, sizeof( ki.password )) == ak_error_ok )
      ki.lenpass = strlen( ki.password );
     else {
       aktool_error(_("incorrect password reading"));
       return exitcode;
     }
  }

 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &master,
                                         ki.password, ki.lenpass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading a master key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ абонента */
  if( ki.verbose ) {
    if( strlen( ki.user_id ) == ki.lenuser )
      printf(_("generation a %s key for %s: "), ki.algorithm->name[0], ki.user_id );
     else printf(_("generation a %s key for %s: "), ki.algorithm->name[0],
                                             ak_ptr_to_hexstr( ki.user_id, ki.lenuser, ak_false ));
    fflush( stdout );
  }
  if( ak_blomkey_create_abonent_key( &abonent, &master, ki.user_id, ki.lenuser ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of the abonent's key"));
    goto labex1;
  }
  if( ki.verbose ) { printf(_("Ok\n")); }

 /* запрашиваем пароль для сохранения ключа абонента */
  ki.lenpass = 0;
  memset( ki.password, 0, sizeof( ki.password ));
  if( aktool_key_load_user_password_twice() != ak_error_ok ) goto labex2;

 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &abonent,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s"), ki.os_file );
     else {
       printf(_("secret key stored in %s\n"), ki.os_file );
       exitcode = EXIT_SUCCESS;
     }

 labex2:
   ak_blomkey_destroy( &abonent );
 labex1:
   ak_blomkey_destroy( &master );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_new_blom_pairwise( void )
{
  ak_oid oid = NULL;
  struct blomkey abonent;
  int exitcode = EXIT_FAILURE;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or abonent's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with abonent's key is undefined, use \"--key\" option" ));
    return exitcode;
  }
  if( strlen( ki.target ) == 0 ) {
    aktool_error(_("the algorithm for the pairwise key must be specified, use \"--target\" option" ));
    return exitcode;
  }
  if( strncmp( ki.target, "undefined", 9 ) != 0 ) {
    if(( oid = ak_oid_find_by_ni( ki.target )) == NULL ) {
      aktool_error(_("wrong name or identifier for the pairwise key's algorithm (%s)" ),
                                                                                       ki.target );
      return exitcode;
    }
    if( oid->mode != algorithm ) {
      aktool_error(_("a name or identifier that is not an algorithm is used (%s)" ),
                                                          ak_libakrypt_get_mode_name( oid->mode ));
      return exitcode;
    }
    switch( oid->engine ) {
      case block_cipher:
      case hmac_function:
      case sign_function:
        break;

      default:
        aktool_error(_("an engine of the given algorithm is not supported (%s)" ),
                                                      ak_libakrypt_get_engine_name( oid->engine ));
        return exitcode;
    }
  }

 /* запрашиваем пароль для доступа к ключу абонента (однократно, без дублирования) */
  if( ki.verbose ) printf(_("abonent key: %s\n"), ki.key_file );
  if( ki.lenpass == 0 ) {
    if( aktool_key_load_user_password( ki.password, sizeof( ki.password )) == ak_error_ok )
      ki.lenpass = strlen( ki.password );
     else {
       aktool_error(_("incorrect password reading"));
       return exitcode;
     }
  }
 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &abonent,
                                         ki.password, ki.lenpass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading an abonent key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ парной связи */
  if( ki.verbose ) {
    if( strlen( ki.user_id ) == ki.lenuser )
      printf(_("generation a pairwise key for %s: "), ki.user_id );
     else printf(_("generation a pairwise key for %s: "),
                                             ak_ptr_to_hexstr( ki.user_id, ki.lenuser, ak_false ));
    fflush( stdout );
  }
  if( !oid ) { /* вырабатываем незашированный вектор */
    time_t atime;
    struct file fs;
    struct hash ctx;
    ak_uint8 key[64], buffer[64];

    if( ak_blomkey_create_pairwise_key_as_ptr( &abonent,
                                   ki.user_id, ki.lenuser, key, abonent.count ) != ak_error_ok ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
    }
    if( ki.verbose ) { printf(_("Ok\n")); }
    if( strlen( ki.os_file ) == 0 ) {
      /* вырабатываем случайное имя файла */
      memset( buffer, 0, sizeof( buffer ));
      memcpy( buffer, ki.user_id, ak_min( ki.lenuser, sizeof( buffer )));
      atime = time( NULL );
      memcpy( buffer + ( sizeof( buffer ) - sizeof( time_t )), &atime, sizeof( time_t ));
      ak_hash_create_streebog512( &ctx );
      ak_hash_ptr( &ctx, buffer, sizeof( buffer ), buffer, sizeof( buffer ));
      ak_hash_destroy( &ctx );
      ak_snprintf( ki.os_file, sizeof( ki.os_file ),
                                       "%s-pairwise.key", ak_ptr_to_hexstr( buffer, 8, ak_false ));
    }
    if( ak_file_create_to_write( &fs, ki.os_file ) != ak_error_ok ) {
      aktool_error(_("incorrect key file creation"));
      goto labex1;
    }
    if( ak_file_write( &fs, key, abonent.count ) != abonent.count ) {
      aktool_error(_("incorrect write to key file"));
    }
     else {
       printf(_("secret key stored in %s file\n"), ki.os_file );
       exitcode = EXIT_SUCCESS;
     }
    ak_file_close( &fs );
  } /* конец генерации undefined key */

   else { /* вырабатываем секретный ключ для заданного опцией --target алгоритма */
     ak_pointer key = NULL;
     if(( key = ak_blomkey_new_pairwise_key( &abonent, ki.user_id, ki.lenuser, oid )) == NULL ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
     }
     if( ki.verbose ) { printf(_("Ok\n")); }

    /* вот еще что надо бы не забыть */
     if( strlen( ki.keylabel ) != 0 ) {
       if( ki.verbose ) printf(_("key label: %s\n"), ki.keylabel );
       ak_skey_set_label( (ak_skey)key, ki.keylabel, 0 );
     }

    /* запрашиваем пароль для сохранения ключа абонента */
     ki.lenpass = 0;
     memset( ki.password, 0, sizeof( ki.password ));
     if( aktool_key_load_user_password_twice() != ak_error_ok ) goto labex2;
   /* теперь экпортируем ключ */
     if( ak_skey_export_to_file_with_password(
          key,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
         ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
       ) != ak_error_ok ) aktool_error(_("wrong export a secret key to file %s"), ki.os_file );
     else {
       printf(_("secret key stored in %s\n"), ki.os_file );
       exitcode = EXIT_SUCCESS;
     }
     labex2: ak_oid_delete_object( oid, key );
  }

 labex1:
   ak_blomkey_destroy( &abonent );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom( void )
{
  switch( ki.algorithm->engine ) {
    case blom_master: return aktool_key_new_blom_master();
    case blom_abonent: return aktool_key_new_blom_abonent();
    case blom_pairwise: return aktool_key_new_blom_pairwise();

    default:
      aktool_error(_("the string %s (%s) cannot be used in blom scheme secret keys generation"),
                                                      ki.algorithm->name[0], ki.algorithm->id[0] );
  }
 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- *
 \param create_secret флаг должен установлен для создания секретного ключа
 \param create_pair флаг должен быть установлен для генерации пары асимметричных ключей
 * ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( bool_t create_secret , bool_t create_pair )
{
  int error = ak_error_ok;
  time_t now = time( NULL );
  char password2[ aktool_password_max_length ];
  ak_pointer key = NULL, generator = NULL;

  if( !create_secret ) return EXIT_FAILURE;
  if( ki.name_of_file_for_generator != NULL ) {
    if(( error = ak_random_create_file( generator = malloc( sizeof( struct random )),
                                               ki.name_of_file_for_generator )) != ak_error_ok ) {
      if( generator ) free( generator );
      return EXIT_FAILURE;
    }
  }
   else
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return EXIT_FAILURE;

 /* создаем ключ */
  if(( key = ak_oid_new_object( ki.algorithm )) == NULL ) goto lab1;

 /* для асимметричных ключей устанавливаем кривую */
  if( ki.algorithm->engine == sign_function ) {
    if(( error = ak_signkey_set_curve( key, ki.curve->data )) != ak_error_ok ) {
      aktool_error(_("using non applicable elliptic curve (%s)"), ki.curve->name[0] );
      goto lab2;
    }
  }

 /* вырабатываем случайный секретный ключ */
  if(( error = ki.algorithm->func.first.set_key_random( key, generator )) != ak_error_ok ) {
    aktool_error(_("incorrect creation of a random secret key value"));
    goto lab2;
  }

 /* устанавливаем срок действия, в сутках, начиная с текущего момента */
  if(( error = ak_skey_set_validity( key, now, now + ki.days*86400 )) != ak_error_ok ) {
    aktool_error(_("incorrect assigning the validity of secret key"));
    goto lab2;
  }

 /* устанавливаем метку */
  if( strlen( ki.keylabel ) > 0 ) {
    if(( error = ak_skey_set_label( key, ki.keylabel, strlen( ki.keylabel ))) != ak_error_ok ) {
      aktool_error(_("incorrect assigning the label of secret key"));
      goto lab2;
    }
  }

  if( create_pair ) { /* телодвижения для асимметричных ключей */
    struct verifykey vkey;

   /* вырабатываем открытый ключ,
      это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
    if(( error = ak_verifykey_create_from_signkey( &vkey, key )) != ak_error_ok ) {
      aktool_error(_("incorrect creation of public key"));
      goto lab2;
    }
   /* создаем обобщенное имя владельца ключей */
    if( aktool_key_input_name( &vkey ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of owner's distinguished name"));
      goto lab2;
    }

    if( ki.format == aktool_magic_number ) { /* сохраняем открытый ключ как корневой сертификат */

     /* для корневого (самоподписанного) сертификата обязательно устанавливаем бит keyCertSign */
      ki.opts.key_usage.is_present = ak_true;
      if(( ki.opts.key_usage.bits&bit_keyCertSign ) == 0 ) {
        ki.opts.key_usage.bits = ( ki.opts.key_usage.bits&(~bit_keyCertSign ))^bit_keyCertSign;
      }

      ki.format = asn1_pem_format; /* возвращаем необходимое значение */
      if( ak_verifykey_export_to_certificate( &vkey, key, &vkey, generator,  &ki.opts,
                          ki.op_file, ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ),
                                                                     ki.format ) != ak_error_ok ) {
        aktool_error(_("wrong export a public key to certificate %s"), ki.op_file );
        goto lab2;
      }
       else printf(_("certificate of public key stored in %s file\n"), ki.op_file );
    }
     else { /* сохраняем запрос на сертификат */
        if( ak_verifykey_export_to_request( &vkey, key, generator, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
          aktool_error(_("wrong export a public key to request %s"), ki.op_file );
          goto lab2;
        } else
            printf(_("public key stored in %s file as certificate's request\n"), ki.op_file );
     }

    ak_verifykey_destroy( &vkey );
  } /* конец if( create_pair ) */

 /* мастерим пароль для сохранения секретного ключа */
  if( aktool_key_load_user_password_twice() != ak_error_ok ) goto lab2;

 /* сохраняем созданный ключ в файле */
  if( ak_skey_export_to_file_with_password(
          key,             /* ключ */
          ki.password,     /* пароль */
          ki.lenpass,      /* длина пароля */
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
     ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s"), ki.os_file );
     goto lab2;
  } else {
     /* секретный ключ хорошо хранить в хранилище */
     printf(_("secret key stored in %s\n"), ki.os_file );
    }

 /* удаляем память */
  lab2:
   ak_oid_delete_object( ki.algorithm, key );

  lab1:
   if( ki.name_of_file_for_generator != NULL ) {
     ak_random_destroy( generator );
     free( generator );
   }
    else ak_oid_delete_object( ki.oid_of_generator, generator );

 /* очищаем память */
  memset( password2, 0, sizeof( password2 ));
  memset( &ki, 0, sizeof( struct key_info ));

 return ( error == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_certificate( void )
{
  aktool_error(_("this feature is not implemented yet"));
 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name( ak_verifykey key )
{
  size_t len = 0;
  char string[256];
  bool_t noname = ak_true;

 /* 0. Выводим стандартное пояснение */
  aktool_key_print_disclaimer();

 /* в короткой форме мы можем запросить флаги
               /ct/st/ln/or/ou/sa/cn/su/em/sn */

 /* 1. Country Name */
  ak_snprintf( string, len = sizeof( string ), "RU" );
  if( ak_string_read(_("Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
   #ifdef AK_HAVE_CTYPE_H
    string[0] = toupper( string[0] );
    string[1] = toupper( string[1] );
   #endif
    string[2] = 0;
    if( len && ( ak_verifykey_add_name_string( key,
                                      "country-name", string ) == ak_error_ok )) noname = ak_false;
  }
 /* 2. State or Province */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("State or Province"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                            "state-or-province-name", string ) == ak_error_ok )) noname = ak_false;
 /* 3. Locality */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Locality (eg, city)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "locality-name", string ) == ak_error_ok )) noname = ak_false;
 /* 4. Organization */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization (eg, company)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                      "organization", string ) == ak_error_ok )) noname = ak_false;
 /* 5. Organization Unit*/
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization Unit"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                 "organization-unit", string ) == ak_error_ok )) noname = ak_false;
 /* 6. Street Address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Street Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                    "street-address", string ) == ak_error_ok )) noname = ak_false;
 /* 7. Common Name */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Common Name"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                       "common-name", string ) == ak_error_ok )) noname = ak_false;
 /* 8. email address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Email Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "email-address", string ) == ak_error_ok )) noname = ak_false;
  if( noname ) {
    aktool_error(
   _("generation of a secret or public keys without any information about owner are not allowed"));
    return ak_error_invalid_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_print_disclaimer( void )
{
  printf(_(" -----\n"
   " You are about to be asked to enter information that will be incorporated\n"
   " into your certificate request.\n"
   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
   " There are quite a few fields but you can leave some blank.\n"
   " For some fields there will be a default value.\n"
   " If you do not want to provide information just enter a string of one or more spaces.\n"
   " -----\n"));

 return ak_error_ok;
}

// СДЕЛАТЬ -c <request> с параметром, а опцию --req удалить
// Сделать -subj = "/cn/su/sn/ct/ln/st/or/ou/em"

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     "available options:\n"
     " -a, --algorithm         specify the name of the cryptographic algorithm for the new key\n"
     "                         one can use any supported names or identifiers of algorithm\n"
     " -c, --cert              create a public key certificate from a given request\n"
     "     --curve             set the elliptic curve identifier for public keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --field             bit length which used to define the galois field [ enabled values: 256, 512 ]\n"
     "     --hexid             user or abonent's identifier as hexademal string\n"
     "     --hexload           input the password from console as hexademal string\n"
     "     --hexpass           specify the password directly in command line as hexademal string\n"
     "     --id                user or abonent's identifier\n"
     "     --key               specify the name of file with the secret key\n"
     "                         (this can be a master key or issuer's key which is used to sign a certificate)\n"
     "     --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified algorithm\n"
     "     --op                short form of --output-public-key option\n"
     "     --output-public-key set the file name for the new public key request\n"
     " -o, --output-secret-key set the file name for the new secret key\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
     "     --pubkey            name of the issuer's public key, information from which will be placed in the certificate\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used to create a new key [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     "     --req               set the name of request to certificate which would be signed\n"
     "     --size              set the dimension of secret master key in blom scheme [ maximal value: 4096 ]\n"
     "     --target            specify target algorithm for generated pairwise key\n"
     "                         one can use \"undefined\" value for generation plain unecrypted key\n"
     "     --to                set the format of output file [ enabled values: der, pem, certificate ]\n\n"
     "options used for customizing a public key's certificate:\n"
     "     --authority-keyid   add an authority key identifier to certificate being created\n"
     "                         this option should only be used for self-signed certificates,\n"
     "                         in other cases it is used by default\n"
     "     --authority-name    add an issuer's generalized name to the authority key identifier extension\n"
     "     --ca                use as certificate authority [ enabled values: true, false ]\n"
     "     --pathlen           set the maximal length of certificate's chain\n"
     "     --digital-signature use for verifying a digital signatures of user data\n"
     "     --content-commitment\n"
     "     --key-encipherment  use for encipherment of secret keys\n"
     "     --data-encipherment use for encipherment of user data (is not usally used)\n"
     "     --key-agreement     use in key agreement protocols for subject's authentication\n"
     "     --key-cert-sign     use for verifying of public key's certificates\n"
     "     --crl-sign          use for verifying of revocation lists of certificates\n"
  ),
  aktool_default_generator
 );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   aktool_key.c  */
/* ----------------------------------------------------------------------------------------------- */
