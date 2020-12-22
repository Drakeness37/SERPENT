 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( int argc, char *argv[] )
{
  struct verifykey vkey;
  struct certificate_opts opts;
  int error = ak_error_ok;

  ak_libakrypt_create( ak_function_log_stderr );

//  printf("verify: %d\n",
//                     error = ak_verifykey_import_from_certificate( &vkey, NULL, "ca.crt", &opts ));
//  if( error != ak_error_ok ) goto lab1;

//  printf(" public key: %s (%s)\n", vkey.oid->name[0], vkey.oid->id[0] );
//  printf(" subject key number: %s\n", ak_ptr_to_hexstr( vkey.number, 32, ak_false ));

//  if( opts.key_usage.is_present ) {
//    printf("key usage: ");
//    if( opts.key_usage.bits&bit_decipherOnly) printf("decipher, ");
//    if( opts.key_usage.bits&bit_encipherOnly) printf("encipher, ");
//    if( opts.key_usage.bits&bit_cRLSign) printf("crl sign, ");
//    if( opts.key_usage.bits&bit_keyCertSign) printf("cert sign, ");
//    printf("\n");
//  }




//  ak_verifykey_destroy( &vkey );

  lab1: ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
