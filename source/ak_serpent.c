/* ----------------------------------------------------------------------------------------------- */
/*                                                                                                 */
/*                                                                                                 */
/*  Файл ak_serpent.h                                                                              */
/*  - содержит реализацию алгоритма блочного шифрования Serpent                                    */
/* ----------------------------------------------------------------------------------------------- */
#include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief S-box для алгоритма Serpent */
/* ---------------------------------------------------------------------------------------------- */
const static ak_uint32 serpent_s_box[32][16] = {
        { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },
        {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },
        { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },
        { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },
        { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },
        {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },
        { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },
        { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инвертированный S-box для алгоритма Serpent */
/* ---------------------------------------------------------------------------------------------- */
const static ak_uint32 serpent_inv_s_box[32][16] = {
        {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },
        { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },
        {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },
        { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },
        { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },
        { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },
        {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },
        { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 }
};

/*! \brief Развернутые раундовые ключи алгоритма Serpent. */
typedef ak_uint128 ak_serpent_expanded_keys[33];

/*! \brief Золотое сечение */
static const ak_uint32 phi = 0x9e3779b9;

/* ---------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
ak_uint32 ak_uint32_cyclic_bit_shift (const ak_uint32 elem, const ak_uint8 shift)
{
    return ((elem << shift) | (elem >> (32 - shift))) & 0xffffffff;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                функции для работы с контекстом                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Serpent.
    \param skey Указатель на контекст секретного ключа, содержащего развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_serpent_delete_keys( ak_skey skey )
{
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                __func__ , "using a null pointer to secret key" );
    if( skey->data != NULL ) {
        /* теперь очистка и освобождение памяти */
        if(( error = ak_ptr_wipe( skey->data, sizeof( ak_serpent_expanded_keys ),
                                  &skey->generator )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect wiping an internal data" );
            memset( skey->data, 0, sizeof( ak_serpent_expanded_keys ));
        }
        free( skey->data );
        skey->data = NULL;
    }
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик.
    \param skey Указатель на контекст секретного ключа, в который помещаются развернутые
    раундовые ключи и маски.
    \return Функция возвращает \ref ak_error_ok в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_serpent_schedule_keys( ak_skey skey )
{
    int i = 0, j = 0, k = 0;
    ak_uint32 sub_keys[33][4] = {0};
    ak_uint32 original_divided_key[140];
    ak_uint8 tmp_key_part[4];
    ak_uint128 *result_data;

    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to secret key" );
    if( skey->key_size != 32 ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "unsupported length of secret key" );
    /*проверяем целостность ключа */
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                                        __func__ , "using key with wrong integrity code" );
    /* удаляем былое */
    if( skey->data != NULL ) ak_serpent_delete_keys( skey );

    /* далее, по-возможности, выделяем выравненную память */
    if(( skey->data = ak_aligned_malloc( sizeof( ak_serpent_expanded_keys ))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                 "wrong allocation of internal data" );

    result_data = ( ak_uint128 *)skey->data;

    for( i = 0; i < 8; i++ ) {
        for ( j = 0; j < 4; ++j)
            tmp_key_part[j] = skey->key[i * 4 + j];
        original_divided_key[i] = *(( ak_uint32 *)tmp_key_part);
    }

    for ( i = 8; i < 140; ++i) {
        original_divided_key[i] = ak_uint32_cyclic_bit_shift((original_divided_key[i - 8] ^ original_divided_key[i - 5]
                                                ^ original_divided_key[i - 3] ^ original_divided_key[i - 1] ^ phi ^ (i - 8)), 11);
    }

    for( i = 0; i < 33; ++i) {
        ak_uint8 tmp = 0;
        for( j = 0; j < 32; ++j) {
            tmp = serpent_s_box[(32 + 3 - i) % 8][((original_divided_key[8 + 0 + (4 * i)] >> j) & 1) << 0 |
                                                  ((original_divided_key[8 + 1 + (4 * i)] >> j) & 1) << 1 | ((original_divided_key[8 + 2 + (4 * i)] >> j) & 1) << 2 |
                                                    ((original_divided_key[8 + 3 + (4 * i)] >> j) & 1) << 3 ];
            for( k = 0; k < 4; ++k) {
                sub_keys[i][k] |= ((tmp >> k) & 1) << j;
            }
        }
    }

    for ( i = 0; i < 33; ++i) {
        result_data[i] = ((ak_uint128 *)sub_keys[i])[0];
    }

    ak_ptr_wipe( sub_keys, sizeof( sub_keys ), &skey->generator );
    ak_ptr_wipe( original_divided_key, sizeof( original_divided_key ), &skey->generator );
    ak_ptr_wipe( tmp_key_part, sizeof( tmp_key_part ), &skey->generator );
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
static void ak_serpent_encrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
    int i = 0, j = 0;
    ak_uint128* keys = ( ak_uint128 *)skey->data;
    ak_uint32* key_part;
    ak_uint32 el;
    ak_uint32 original_data_part[4];
    ak_uint32 sh_data_part[4];

    original_data_part[0] = (( ak_uint32 *)in)[0];
    original_data_part[1] = (( ak_uint32 *)in)[1];
    original_data_part[2] = (( ak_uint32 *)in)[2];
    original_data_part[3] = (( ak_uint32 *)in)[3];

    for( i = 0; i < 32; ++i) {
        key_part = (( ak_uint32 *)(keys + i));
        for ( j = 0; j < 4; ++j) {
            sh_data_part[j] = original_data_part[j] ^ key_part[j];
            original_data_part[j] =  0;
        }
        for( j = 0; j < 32; ++j) {
            el = (serpent_s_box[i % 8][((sh_data_part[0] >> (j)) & 1) << 0 | ((sh_data_part[1] >> (j)) & 1) << 1 |
                                ((sh_data_part[2] >> (j)) & 1) << 2 | ((sh_data_part[3] >> (j)) & 1) << 3 ]);

            original_data_part[0] |= ((el >> 0) & 1) << j;
            original_data_part[1] |= ((el >> 1) & 1) << j;
            original_data_part[2] |= ((el >> 2) & 1) << j;
            original_data_part[3] |= ((el >> 3) & 1) << j;
        }
        if(i < 31){

            original_data_part[0] = ak_uint32_cyclic_bit_shift(original_data_part[0], 13);
            original_data_part[2] = ak_uint32_cyclic_bit_shift(original_data_part[2], 3);
            original_data_part[1] = original_data_part[1] ^ original_data_part[0] ^ original_data_part[2];
            original_data_part[3] = original_data_part[3] ^ original_data_part[2] ^ (original_data_part[0] << 3);
            original_data_part[1] = ak_uint32_cyclic_bit_shift(original_data_part[1], 1);
            original_data_part[3] = ak_uint32_cyclic_bit_shift(original_data_part[3], 7);
            original_data_part[0] = original_data_part[0] ^ original_data_part[1] ^ original_data_part[3];
            original_data_part[2] = original_data_part[2] ^ original_data_part[3] ^ (original_data_part[1] << 7);
            original_data_part[0] = ak_uint32_cyclic_bit_shift(original_data_part[0], 5);
            original_data_part[2] = ak_uint32_cyclic_bit_shift(original_data_part[2], 22);
        }
        else{
            key_part = (( ak_uint32 *)(keys + 32));
            ((ak_uint32 *)out)[0] = original_data_part[0] ^ key_part[0];
            ((ak_uint32 *)out)[1] = original_data_part[1] ^ key_part[1];
            ((ak_uint32 *)out)[2] = original_data_part[2] ^ key_part[2];
            ((ak_uint32 *)out)[3] = original_data_part[3] ^ key_part[3];
        }
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
static void ak_serpent_decrypt( ak_skey skey, ak_pointer in, ak_pointer out )
{
    int i = 0, j = 0;
    ak_uint128* keys = ( ak_uint128 *)skey->data;
    ak_uint32* key_part;
    ak_uint32 el;
    ak_uint32 original_data_part[4];
    ak_uint32 sh_data_part[4] = {0};

    original_data_part[0] = (( ak_uint32 *)in)[0];
    original_data_part[1] = (( ak_uint32 *)in)[1];
    original_data_part[2] = (( ak_uint32 *)in)[2];
    original_data_part[3] = (( ak_uint32 *)in)[3];


    for( i = 31; i >= 0; --i) {


        if(i < 31){
            key_part = (( ak_uint32 *)(keys + i));
            original_data_part[2] = ak_uint32_cyclic_bit_shift(original_data_part[2], 10) ^ original_data_part[3] ^ (original_data_part[1] << 7);
            original_data_part[0] = ak_uint32_cyclic_bit_shift(original_data_part[0], 27) ^ original_data_part[1] ^ original_data_part[3];
            original_data_part[3] = ak_uint32_cyclic_bit_shift(original_data_part[3], 25);
            original_data_part[1] = ak_uint32_cyclic_bit_shift(original_data_part[1], 31);
            original_data_part[3] = original_data_part[3] ^ original_data_part[2] ^ (original_data_part[0] << 3);
            original_data_part[1] = original_data_part[1] ^ original_data_part[0] ^ original_data_part[2];
            original_data_part[2] = ak_uint32_cyclic_bit_shift(original_data_part[2], 29);
            original_data_part[0] = ak_uint32_cyclic_bit_shift(original_data_part[0], 19);
        }
        else{
            key_part = (( ak_uint32 *)(keys + 32));
            original_data_part[0] = original_data_part[0] ^ key_part[0];
            original_data_part[1] = original_data_part[1] ^ key_part[1];
            original_data_part[2] = original_data_part[2] ^ key_part[2];
            original_data_part[3] = original_data_part[3] ^ key_part[3];
        }
        for( j = 0; j < 32; ++j) {
            el = (serpent_inv_s_box[i % 8][((original_data_part[0] >> (j)) & 1) << 0 | ((original_data_part[1] >> (j)) & 1) << 1 |
                                       ((original_data_part[2] >> (j)) & 1) << 2 | ((original_data_part[3] >> (j)) & 1) << 3 ]);

            sh_data_part[0] |= ((el >> 0)&1) << j;
            sh_data_part[1] |= ((el >> 1)&1) << j;
            sh_data_part[2] |= ((el >> 2)&1) << j;
            sh_data_part[3] |= ((el >> 3)&1) << j;
        }
        if (i == 31)
            key_part = (( ak_uint32 *)(keys + i));
        for ( j = 0; j < 4; ++j) {
            original_data_part[j] = sh_data_part[j] ^ key_part[j];
            sh_data_part[j] =  0;
        }
    }

    ((ak_uint32 *)out)[0] = original_data_part[0];
    ((ak_uint32 *)out)[1] = original_data_part[1];
    ((ak_uint32 *)out)[2] = original_data_part[2];
    ((ak_uint32 *)out)[3] = original_data_part[3];
    ak_ptr_wipe( key_part, sizeof( key_part ), &skey->generator );
}

/* ----------------------------------------------------------------------------------------------- */
/*! После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    \param bkey Контекст секретного ключа алгоритма блочного шифрования.
    \return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_serpent( ak_bckey bkey )
{
    int error = ak_error_ok, oc = (int) ak_libakrypt_get_option_by_name( "openssl_compability" );

    if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to block cipher key context" );
    if(( oc < 0 ) || ( oc > 1 )) return ak_error_message( ak_error_wrong_option, __func__,
                                                          "wrong value for \"openssl_compability\" option" );

    /* создаем ключ алгоритма шифрования и определяем его методы */
    if(( error = ak_bckey_create( bkey, 32, 16 )) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong initalization of block cipher key context" );

    /* устанавливаем OID алгоритма шифрования */
    if(( bkey->key.oid = ak_oid_find_by_name( "serpent" )) == NULL ) {
        ak_error_message( error = ak_error_get_value(), __func__,
                          "wrong search of predefined serpent block cipher OID" );
        ak_bckey_destroy( bkey );
        return error;
    }

    /* ресурс ключа устанавливается в момент присвоения ключа */

    /* устанавливаем методы */
    bkey->schedule_keys = ak_serpent_schedule_keys;
    bkey->delete_keys = ak_serpent_delete_keys;
    bkey->encrypt = ak_serpent_encrypt;
    bkey->decrypt = ak_serpent_decrypt;
    return error;
}
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_serpent.c    */
/* ----------------------------------------------------------------------------------------------- */

