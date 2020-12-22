 #include <stdio.h>
 #include <libakrypt-base.h>

/* определяем функцию, которая должна выполять содержательую работу
                        по разбору данных, считываемых из ini-файла */
 int user_handler( void *user , const char *section , const char *name , const char *value )
{
 printf("section [%s]: name [%s] = value [%s]\n", section, name, value );
 return 1; /* ненулевое значение - успешное завершение обработчика */
}

 int main( void )
{
 const char *string =
   "[example-ini]\n"
   "  file-name = example-ini.c\n"
   "  description = used as example for reading ini files\n"; 

 /* устанавливаем стандартную функцию аудита */
   ak_log_set_function( ak_function_log_stderr );

 if( ak_ini_parse_string( string, user_handler, NULL ) != ak_error_ok )
   printf("incorrect parsing of test string\n");
  
 return 0;
}
