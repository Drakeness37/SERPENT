 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show_help( void );
 void aktool_show_oid( const size_t , ak_oid );
 int aktool_show_secret_key( const char * );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show( int argc, tchar *argv[] )
{
  size_t idx = 0;
  char *value = NULL;
  oid_modes_t mode = algorithm;
  oid_engines_t engine = identifier;
  int next_option = 0, show_caption = ak_true, result = EXIT_SUCCESS;
  enum { do_nothing, do_alloids, do_oid, do_engines,
                                        do_modes, do_options, do_curve, do_key } work = do_nothing;
 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
     { "oids",             0, NULL,  254 },
     { "oid",              1, NULL,  253 },
     { "engines",          0, NULL,  252 },
     { "options",          0, NULL,  251 },
     { "without-caption",  0, NULL,  250 },
     { "modes",            0, NULL,  249 },
     { "curve",            1, NULL,  220 },
     { "key",              1, NULL,  'k' },

     { "openssl-style",    0, NULL,   5  },
     { "audit",            1, NULL,   4  },
     { "dont-use-colors",  0, NULL,   3  },
     { "audit-file",       1, NULL,   2  },
     { "help",             0, NULL,   1  },
     { NULL,               0, NULL,   0  },
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "k:", long_options, NULL );
       switch( next_option )
      {
        case  1  :   return aktool_show_help();
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


        case 254 : /* выводим список всех доступных oid */
                     work = do_alloids;
                     break;
        case 253 : /* производим поиск OID по параметрам */
                     work = do_oid; value = optarg;
                     break;
        case 252 : /* выводим список всех типов криптографических механизмов */
                     work = do_engines;
                     break;
        case 251 : /* выводим список всех опций библиотеки и их значений */
                     work = do_options;
                     break;
        case 250:  /* запрещаем выводить заголовок */
                     show_caption = ak_false;
                     break;
        case 249:  /* выводим список всех режимов работы */
                     work = do_modes;
                     break;
        case 220:  /* выводим параметры заданной эллиптической кривой */
                     work = do_curve; value = optarg;
                     break;
        case 'k':  /* выводим информацию о заданном секретном ключе */
                     work = do_key; value = optarg;
                     break;
        default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_show_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_alloids: /* выводим список всех доступных oid */
       if( show_caption ) {
         printf("  N  %-25s %-40s %-20s %-20s\n", _("oid(s)"), _("name(s)"), _("engine"), _("mode"));
         printf(" -----------------------------------------------------");
         printf("------------------------------------------------------\n");
       }
       for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
         ak_oid oid = ak_oid_find_by_index( idx );
         if( oid ) aktool_show_oid( idx, oid );
       }
       break;

     case do_oid: /* выводим список тех, кто подходит под заданный шаблон */
       if( show_caption ) {
         printf("  N  %-25s %-40s %-20s %-20s\n", _("oid(s)"), _("name(s)"), _("engine"), _("mode"));
         printf(" -----------------------------------------------------");
         printf("------------------------------------------------------\n");
       }

       for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
          size_t jdx = 0;
          ak_oid oid = ak_oid_find_by_index( idx );

         /* получаем информацию об идентифкаторе с заданным номером */
          if( oid == NULL ) break;

         /* проверяем тип криптопреобразования (engine) */
          if( strstr( ak_libakrypt_get_engine_name( oid->engine ), value ) != NULL ) goto jump;
         /* проверяем режим криптопреобразования (mode) */
          if( strstr( ak_libakrypt_get_mode_name( oid->mode ), value ) != NULL ) goto jump;
         /* поиск по идентификатору */
          jdx = 0;
          while( oid->id[jdx] != NULL ) {
            if( strstr( oid->id[jdx], value ) != NULL ) goto jump;
            ++jdx;
          }
         /* поиск по имени */
          jdx = 0;
          while( oid->name[jdx] != NULL ) {
            if( strstr( oid->name[jdx], value ) != NULL ) goto jump;
            ++jdx;
          }
          continue;
          jump: aktool_show_oid( idx, oid );
       }
       break;

    /* выводим информацию о текущем состоянии опций библиотеки */
     case do_options:
       if( show_caption ) {
         printf(" %-40s %-16s\n", _("option"), _("value"));
         printf("------------------------------------------------------\n");
       }
       for( idx = 0; idx < ak_libakrypt_options_count(); idx++ ) {
         #ifndef __MINGW32__
          printf(" %-40s %-16lld\n",
                   ak_libakrypt_get_option_name( idx ), ak_libakrypt_get_option_by_index( idx ));
         #else
          printf(" %-40s %-16ld\n", ak_libakrypt_get_option_name( idx ),
                                             (long int) ak_libakrypt_get_option_by_index( idx ));
         #endif
       }
       break;

     case do_engines:
       if( show_caption )
         printf(" %s\n------------------------------------------------------\n", _("engine"));

       do {
           printf(" %s\n", ak_libakrypt_get_engine_name( engine ));
       } while( engine++ < undefined_engine );
       break;

     case do_modes:
       if( show_caption )
         printf(" %s\n------------------------------------------------------\n", _("mode"));
       do {
            printf(" %s\n", ak_libakrypt_get_mode_name( mode ));
       } while( mode++ < undefined_mode );
       break;

     case do_curve:
       if( ak_libakrypt_print_curve( stdout, value ) != ak_error_ok ) {
         aktool_error(_("using incorrect elliptic curve name or identifier"));
         aktool_error(_("try \"aktool s --oid curve\" to list all supported elliptic curves"));
       }
       break;

     case do_key:
       if(( result = aktool_show_secret_key( value )) == EXIT_FAILURE )
         aktool_error(_("using a file %s that does not contain secret key information"), value );
       break;

     default:  break;
   }
 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 void aktool_show_oid( size_t idx, ak_oid oid )
{
  size_t ilen = 0, nlen = 0, jdx = 0;

 /* выводим сначала с одним именем  */
  printf("%3u  %-25s %-40s %-20s %-20s\n",
         (unsigned int) idx+1, oid->id[0], oid->name[0],
         ak_libakrypt_get_engine_name( oid->engine ), ak_libakrypt_get_mode_name( oid->mode ));

 /* потом выводим остальные имена идентификатора */
  while( oid->id[++ilen] != NULL );
  while( oid->name[++nlen] != NULL );

  for( jdx = 1; jdx < ak_max( ilen, nlen ); jdx++ ) {
    if(( jdx < ilen ) && ( oid->id[jdx] != NULL )) printf("%-3s  %-26s", " " , oid->id[jdx] );
      else printf("%-3s  %-26s", " " , " " );
    if(( jdx < nlen ) && ( oid->name[jdx] != NULL )) printf("%s\n", oid->name[jdx] );
      else printf("%s\n", " " );
  }
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show_secret_key( const char *filename )
{
 /* создаем контекст ключа (без считывания ключевой информации, только параметры) */
  ak_pointer key = ak_skey_new_from_file( filename );
  ak_skey skey = (ak_skey)key;

  if( key == NULL ) return EXIT_FAILURE;

 /* теперь, последовательно, выводим считанную информацию */
  printf("%13s: %s (%s)\n", ak_libakrypt_get_engine_name( skey->oid->engine ),
                                                            skey->oid->name[0], skey->oid->id[0] );
  printf(_("       number: %s\n"), ak_ptr_to_hexstr( skey->number, 32, ak_false ));
  printf(_("        label: %s\n"), skey->label );
  printf(_("     resource: %ld (%s)\n"), (long int)( skey->resource.value.counter ),
                              ak_libakrypt_get_counter_resource_name( skey->resource.value.type ));

  printf(_("   not before: %s"), ctime( &skey->resource.time.not_before ));
  printf(_("    not after: %s"), ctime( &skey->resource.time.not_after ));

 /* для асимметричных секретных ключей выводим дополнительную информацию */
  if( skey->oid->engine == sign_function ) {
    ak_oid curvoid = ak_oid_find_by_data( skey->data );
    printf("        curve: ");
    if( curvoid == NULL ) printf(_("undefined\n"));
      else printf("%s (%s)\n", curvoid->name[0], curvoid->id[0] );
    printf(_("   verify key: %s\n"),
                             ak_ptr_to_hexstr(((ak_signkey)key)->verifykey_number, 32, ak_false ));
  }
  printf(_("         file: %s\n"), filename );
  ak_oid_delete_object( ((ak_skey)key)->oid, key );

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show_help( void )
{
  printf(
   _("aktool show [options]  - show useful information about keys and libakrypt parameters\n\n"
     "available options:\n"
     "     --curve <ni>        show the parameters of elliptic curve with given name or identifier\n"
     "     --engines           show all types of available crypto engines\n"
     " -k, --key <file>        output the parameters of the secret key (symmetric or asymmetric)\n"
     "     --oid <enim>        show one or more OID's,\n"
     "                         where \"enim\" is an engine, name, identifier or mode of OID\n"
     "     --oids              show the list of all available libakrypt's OIDs\n"
     "     --options           show the list of all libakrypt's cryptographic options and their values\n"
     "     --modes             show all types of cryptographic modes\n"
     "     --without-caption   don't show a caption for displayed values\n"
  ));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_show.c  */
/* ----------------------------------------------------------------------------------------------- */
