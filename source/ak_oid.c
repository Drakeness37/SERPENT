/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_oid.с                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*                           функции для доступа к именам криптоалгоритмов                         */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_engine_names[] = {
    "identifier",
    "block cipher",
    "stream cipher",
    "hybrid cipher",
    "hash function",
    "hmac function",
    "cmac function",
    "mgm function",
    "mac function",
    "sign function",
    "verify function",
    "random generator",
    "oid engine",
    "master key",
    "abonent key",
    "pairwise key",
    "undefined engine",
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_mode_names[] = {
    "algorithm",
    "parameter",
    "wcurve params",
    "ecurve params",
    "kbox params",
    "encrypt mode",
    "encrypt2k mode",
    "acpkm",
    "mac",
    "aead",
    "xcrypt",
    "descriptor",
    "undefined mode"
};

/*! \addtogroup oid-doc

  \ref oid (Object IDentifier) это уникальная последовательность чисел, разделенных точками.
  Уникальный идентификатор может быть присвоен любому криптографическому механизму (алгоритму,
  схеме, протоколу), а также произвольным параметрам этих механизмов.
  Использование OID'в позволяет однозначно определять тип криптографического механизма или
  значения его параметров на этапе выполнения программы, а также
  однозначно связывать данные (как правило ключевые) с алгоритмами, в которых эти данные
  используются.

  Все \ref oid образуют одно большое дерево,
  поддерживаемое уполномоченными на то организациями в соответствии с международным стандартом [ГОСТ Р ИСО/МЭК 9834-1-2009](https://files.stroyinf.ru/Data2/1/4293825/4293825307.pdf).

  Корень российского дерева идентификаторов образует идентификатор `1.2.643`.
  Далее дерево выглядит следующим образом

    - `1.2.643.1`  Операторы связи (communication organization)
    - `1.2.643.2`  [Производители программного обеспечения](https://oid.iitrust.ru/oid_search/11/) (program organization)
    - `1.2.643.3`  Удостоверяющие центры (certificate authority)
    - `1.2.643.4`  Банки (banks)
    - `1.2.643.5`  Органы власти и государственные организации (government organization)
    - `1.2.643.6`  Прочие организации (another organization)
    - `1.2.643.7`  Организации по стандартизации (organization of standardization); сюда, в частности,
    входит Технический комитет по стандартизации ТК26 "Криптографическая защита информации"
    - `1.2.643.8`  Образовательные организации (organization of education)
    - `1.2.643.9`  Муниципальные образования (municipalities)
    - `1.2.643.10` Индивидуальные предприниматели (individual businessman)

  Библиотека `libakrypt` поддерживает свое собственное дерево идентификаторов, корнем
  которого служит последовательность `1.2.643.2.52.1`.
  Данные значения используются в случае, когда идентификаторы алгоритмов не определены
  ни рекомендациями ТК 26, ни существующими реализациями других производителей
  программного обеспечения.

  Поддеревья алгоритмов и их параметров определяются следующим образом.

  - `1.2.643.2.52.1.1` генераторы псевдо-случайных чисел,
  - `1.2.643.2.52.1.2` алгоритмы поточного шифрования,
  - `1.2.643.2.52.1.3` режимы работы поточных шифров,
  - `1.2.643.2.52.1.4` алгоритмы блочного шифрования,
  - `1.2.643.2.52.1.5` базовые режимы работы блочных шифров,
  - `1.2.643.2.52.1.6` расширенные режимы работы блочных шифров,
  - `1.2.643.2.52.1.7` алгоритмы выработки имитовставки,

  - `1.2.643.2.52.1.10` алгоритмы выработки электронной подписи,
  - `1.2.643.2.52.1.11` алгоритмы проверки электронной подписи,
  - `1.2.643.2.52.1.12` параметры эллиптических кривых

  - `1.2.643.2.52.1.181` алгоритмы генерации ключевой информации для схемы Блома
  - `1.2.643.2.52.1.127` контейнеры библиотеки

  Техническая реализация класса \ref oid представляет собой структуру,
  связывающую вместе списки имен (каждый \ref oid может иметь несколько имен),
  списки идентификаторов (каждый \ref oid может иметь несколько идентификаторов, присвоенных
  различными организациями), указатель на двоичные данные (это, как правило, явно заданные параметры
  криптографических алгоритмов), а также набор функций,
  позволяющих создавать, удалять и управлять объектами (секретными ключами)
  криптографических преобразований.

  Реализованы функции поиска идентификаторов по заданным именам, идентификаторам,
  а также типам (\ref oid_engines_t) и режимам (\ref oid_modes_t) криптографических преобразований.*/
/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения имен идентификаторов */
 static const char *asn1_lcg_n[] =         { "lcg", NULL };
 static const char *asn1_lcg_i[] =         { "1.2.643.2.52.1.1.1", NULL };
#if defined(__unix__) || defined(__APPLE__)
 static const char *asn1_dev_random_n[] =  { "dev-random", "/dev/random", NULL };
 static const char *asn1_dev_random_i[] =  { "1.2.643.2.52.1.1.2", NULL };
 static const char *asn1_dev_urandom_n[] = { "dev-urandom", "/dev/urandom", NULL };
 static const char *asn1_dev_urandom_i[] = { "1.2.643.2.52.1.1.3", NULL };
#endif
#ifdef _WIN32
 static const char *asn1_winrtl_n[] =       { "winrtl", NULL };
 static const char *asn1_winrtl_i[] =       { "1.2.643.2.52.1.1.4", NULL };
#endif

 static const char *asn1_streebog256_n[] = { "streebog256", "md_gost12_256", NULL };
 static const char *asn1_streebog256_i[] = { "1.2.643.7.1.1.2.2", NULL };
 static const char *asn1_streebog512_n[] = { "streebog512", "md_gost12_512", NULL };
 static const char *asn1_streebog512_i[] = { "1.2.643.7.1.1.2.3", NULL };
 static const char *asn1_hmac_streebog256_n[] = { "hmac-streebog256", "HMAC-md_gost12_256", NULL };
 static const char *asn1_hmac_streebog256_i[] = { "1.2.643.7.1.1.4.1", NULL };
 static const char *asn1_hmac_streebog512_n[] = { "hmac-streebog512", "HMAC-md_gost12_512", NULL };
 static const char *asn1_hmac_streebog512_i[] = { "1.2.643.7.1.1.4.2", NULL };
 static const char *asn1_magma_n[] =       { "magma", NULL };
 static const char *asn1_magma_i[] =       { "1.2.643.7.1.1.5.1", NULL };
 static const char *asn1_kuznechik_n[] =   { "kuznechik", "kuznyechik", "grasshopper", NULL };
 static const char *asn1_kuznechik_i[] =   { "1.2.643.7.1.1.5.2", NULL };
 static const char *asn1_serpent_n[] =   { "serpent", NULL };
 static const char *asn1_serpent_i[] =   { "1.2.643.7.1.1.5.3", NULL };

 static const char *asn1_ctr_magma_n[] =   { "ctr-magma", NULL };
 static const char *asn1_ctr_magma_i[] =   { "1.2.643.2.52.1.5.1.1", NULL };
 static const char *asn1_ctr_kuznechik_n[] =
                                           { "ctr-kuznechik", "ctr-kuznyechik", NULL };
 static const char *asn1_ctr_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.1.2", NULL };
static const char *asn1_ctr_serpent_n[] =
        { "ctr-serpent", "ctr-serpent", NULL };
static const char *asn1_ctr_serpent_i[] =
        { "1.2.643.2.52.1.5.1.3", NULL };
 static const char *asn1_ofb_magma_n[] =   { "ofb-magma", NULL };
 static const char *asn1_ofb_magma_i[] =   { "1.2.643.2.52.1.5.2.1", NULL };
 static const char *asn1_ofb_kuznechik_n[] =
                                           { "ofb-kuznechik", "ofb-kuznyechik", NULL };
 static const char *asn1_ofb_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.2.2", NULL };
static const char *asn1_ofb_serpent_n[] =
        { "ofb-serpent", "ofb-serpent", NULL };
static const char *asn1_ofb_serpent_i[] =
        { "1.2.643.2.52.1.5.2.3", NULL };
 static const char *asn1_cfb_magma_n[] =   { "cfb-magma", NULL };
 static const char *asn1_cfb_magma_i[] =   { "1.2.643.2.52.1.5.3.1", NULL };
 static const char *asn1_cfb_kuznechik_n[] =
                                           { "cfb-kuznechik", "cfb-kuznyechik", NULL };
 static const char *asn1_cfb_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.3.2", NULL };
static const char *asn1_cfb_serpent_n[] =
        { "cfb-serpent", "cfb-serpent", NULL };
static const char *asn1_cfb_serpent_i[] =
        { "1.2.643.2.52.1.5.3.3", NULL };
 static const char *asn1_cbc_magma_n[] =   { "cbc-magma", NULL };
 static const char *asn1_cbc_magma_i[] =   { "1.2.643.2.52.1.5.4.1", NULL };
 static const char *asn1_cbc_kuznechik_n[] =
                                           { "cbc-kuznechik", "cbc-kuznyechik", NULL };
 static const char *asn1_cbc_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.4.2", NULL };
static const char *asn1_cbc_serpent_n[] =
        { "cbc-serpent", "cbc-serpent", NULL };
static const char *asn1_cbc_serpent_i[] =
        { "1.2.643.2.52.1.5.4.3", NULL };

 static const char *asn1_xts_magma_n[] =   { "xts-magma", NULL };
 static const char *asn1_xts_magma_i[] =   { "1.2.643.2.52.1.5.5.1", NULL };
 static const char *asn1_xts_kuznechik_n[] =
                                           { "xts-kuznechik", NULL };
 static const char *asn1_xts_kuznechik_i[] =
                                           { "1.2.643.2.52.1.5.5.2", NULL };
static const char *asn1_xts_serpent_n[] =
        { "xts-serpent", NULL };
static const char *asn1_xts_serpent_i[] =
        { "1.2.643.2.52.1.5.5.3", NULL };

 /*   id-gostr3412-2015-magma-ctracpkm OBJECT IDENTIFIER ::= { 1.2.643.7.1.1.5.1.1 }
      id-gostr3412-2015-kuznechik-ctracpkm OBJECT IDENTIFIER ::= { 1.2.643.7.1.1.5.2.1 } */

 static const char *asn1_acpkm_magma_n[] = { "acpkm-magma",
                                             "id-gostr3412-2015-magma-ctracpkm", NULL };
 static const char *asn1_acpkm_magma_i[] = { "1.2.643.7.1.1.5.1.1", NULL };
 static const char *asn1_acpkm_kuznechik_n[] =
                                           { "acpkm-kuznechik", "acpkm-kuznyechik",
                                             "id-gostr3412-2015-kuznechik-ctracpkm", NULL };
 static const char *asn1_acpkm_kuznechik_i[] =
                                           { "1.2.643.7.1.1.5.2.1", NULL };
static const char *asn1_acpkm_serpent_n[] =
        { "acpkm-serpent", "acpkm-serpent",
          "id-gostr3412-2015-serpent-ctracpkm", NULL };
static const char *asn1_acpkm_serpent_i[] =
        { "1.2.643.7.1.1.5.2.3", NULL };

 static const char *asn1_cmac_magma_n[] =  { "cmac-magma", NULL };
 static const char *asn1_cmac_magma_i[] =  { "1.2.643.2.52.1.7.1.1", NULL };
 static const char *asn1_cmac_kuznechik_n[] =
                                           { "cmac-kuznechik", "cmac-kuznyechik", NULL };
 static const char *asn1_cmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.7.1.2", NULL };
static const char *asn1_cmac_serpent_n[] =
        { "cmac-serpent", "cmac-serpent", NULL };
static const char *asn1_cmac_serpent_i[] =
        { "1.2.643.2.52.1.7.1.3", NULL };
 static const char *asn1_mgm_magma_n[] =   { "mgm-magma",
                                             "id-tc26-cipher-gostr3412-2015-magma-mgm", NULL };
 static const char *asn1_mgm_magma_i[] =   { "1.2.643.7.1.1.5.1.3", NULL };
 static const char *asn1_mgm_kuznechik_n[] =
                                           { "mgm-kuznechik", "mgm-kuznyechik",
                                             "id-tc26-cipher-gostr3412-2015-kuznyechik-mgm", NULL };
 static const char *asn1_mgm_kuznechik_i[] =
                                           { "1.2.643.7.1.1.5.2.3", NULL };
static const char *asn1_mgm_serpent_n[] =
        { "mgm-serpent", "mgm-serpent",
          "id-tc26-cipher-gostr3412-2015-serpent-mgm", NULL };
static const char *asn1_mgm_serpent_i[] =
        { "1.2.643.7.1.1.5.3.3", NULL };
 static const char *asn1_ctr_cmac_magma_n[] =
                                           { "ctr-cmac-magma", NULL };
 static const char *asn1_ctr_cmac_magma_i[] =
                                           { "1.2.643.2.52.1.6.1.1", NULL };
 static const char *asn1_ctr_cmac_kuznechik_n[] =
                                           { "ctr-cmac-kuznechik", NULL };
 static const char *asn1_ctr_cmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.6.1.2", NULL };
static const char *asn1_ctr_cmac_serpent_n[] =
        { "ctr-cmac-serpent", NULL };
static const char *asn1_ctr_cmac_serpent_i[] =
        { "1.2.643.2.52.1.6.1.3", NULL };
 static const char *asn1_ctr_hmac_magma_streebog256_n[] =
                                           { "ctr-hmac-magma-streebog256", NULL };
 static const char *asn1_ctr_hmac_magma_streebog256_i[] =
                                           { "1.2.643.2.52.1.6.2.1.1", NULL };
 static const char *asn1_ctr_hmac_magma_streebog512_n[] =
                                           { "ctr-hmac-magma-streebog512", NULL };
 static const char *asn1_ctr_hmac_magma_streebog512_i[] =
                                           { "1.2.643.2.52.1.6.2.1.2", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog256_n[] =
                                           { "ctr-hmac-kuznechik-streebog256", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog256_i[] =
                                           { "1.2.643.2.52.1.6.2.2.1", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog512_n[] =
                                           { "ctr-hmac-kuznechik-streebog512", NULL };
 static const char *asn1_ctr_hmac_kuznechik_streebog512_i[] =
                                           { "1.2.643.2.52.1.6.2.2.2", NULL };
static const char *asn1_ctr_hmac_serpent_streebog256_n[] =
        { "ctr-hmac-serpent-streebog256", NULL };
static const char *asn1_ctr_hmac_serpent_streebog256_i[] =
        { "1.2.643.2.52.1.6.2.3.1", NULL };
static const char *asn1_ctr_hmac_serpent_streebog512_n[] =
        { "ctr-hmac-serpent-streebog512", NULL };
static const char *asn1_ctr_hmac_serpent_streebog512_i[] =
        { "1.2.643.2.52.1.6.2.3.2", NULL };
 static const char *asn1_xtsmac_magma_n[] =
                                           { "xtsmac-magma", NULL };
 static const char *asn1_xtsmac_magma_i[] =
                                           { "1.2.643.2.52.1.6.3.1", NULL };
 static const char *asn1_xtsmac_kuznechik_n[] =
                                           { "xtsmac-kuznechik", "xtsmac-kuznyechik", NULL };
 static const char *asn1_xtsmac_kuznechik_i[] =
                                           { "1.2.643.2.52.1.6.3.2", NULL };
static const char *asn1_xtsmac_serpent_n[] =
        { "xtsmac-serpent", "xtsmac-serpent", NULL };
static const char *asn1_xtsmac_serpent_i[] =
        { "1.2.643.2.52.1.6.3.3", NULL };

 static const char *asn1_sign256_n[] =     { "id-tc26-signwithdigest-gost3410-12-256",
                                             "sign256", NULL };
 static const char *asn1_sign256_i[] =     { "1.2.643.7.1.1.3.2", NULL };
 static const char *asn1_sign512_n[] =     { "id-tc26-signwithdigest-gost3410-12-512",
                                             "sign512", NULL };
 static const char *asn1_sign512_i[] =     { "1.2.643.7.1.1.3.3", NULL };
 static const char *asn1_verify256_n[] =   { "id-tc26-gost3410-12-256", "verify256", NULL };
 static const char *asn1_verify256_i[] =   { "1.2.643.7.1.1.1.1", NULL };
 static const char *asn1_verify512_n[] =   { "id-tc26-gost3410-12-512", "verify512", NULL };
 static const char *asn1_verify512_i[] =   { "1.2.643.7.1.1.1.2", NULL };

 static const char *asn1_w256_pst_n[] =    { "id-tc26-gost-3410-2012-256-paramSetTest", NULL };
 static const char *asn1_w256_pst_i[] =    { "1.2.643.7.1.2.1.1.0",
                                             "1.2.643.2.2.35.0", NULL };
 static const char *asn1_w256_psa_n[] =    { "id-tc26-gost-3410-2012-256-paramSetA", NULL };
 static const char *asn1_w256_psa_i[] =    { "1.2.643.7.1.2.1.1.1", NULL };
 static const char *asn1_w256_psb_n[] =    { "id-tc26-gost-3410-2012-256-paramSetB",
                                             "id-rfc4357-gost-3410-2001-paramSetA",
                                             "id-rfc4357-2001dh-paramSet",
                                             "cspdh",
                                             "cspa", NULL };
 static const char *asn1_w256_psb_i[] =    { "1.2.643.7.1.2.1.1.2",
                                             "1.2.643.2.2.35.1",
                                             "1.2.643.2.2.36.0", NULL };
 static const char *asn1_w256_psc_n[] =    { "id-tc26-gost-3410-2012-256-paramSetC",
                                             "id-rfc4357-gost-3410-2001-paramSetB",
                                             "cspb", NULL };
 static const char *asn1_w256_psc_i[] =    { "1.2.643.7.1.2.1.1.3",
                                             "1.2.643.2.2.35.2", NULL };
 static const char *asn1_w256_psd_n[] =    { "id-tc26-gost-3410-2012-256-paramSetD",
                                             "id-rfc4357-gost-3410-2001-paramSetC",
                                             "cspc", NULL };
 static const char *asn1_w256_psd_i[] =    { "1.2.643.7.1.2.1.1.4",
                                             "1.2.643.2.2.35.3", NULL };
 static const char *asn1_w256_axel_n[] =   { "id-axel-gost-3410-2012-256-paramSetN0",
                                             "axel-n0", NULL };
 static const char *asn1_w256_axel_i[] =   { "1.2.643.2.52.1.12.1.1", NULL };

/* теперь кривые длиной 512 бит */
 static const char *asn1_w512_pst_n[] =    { "id-tc26-gost-3410-2012-512-paramSetTest", NULL };
 static const char *asn1_w512_pst_i[] =    { "1.2.643.7.1.2.1.2.0", NULL };
 static const char *asn1_w512_psa_n[] =    { "id-tc26-gost-3410-2012-512-paramSetA", NULL };
 static const char *asn1_w512_psa_i[] =    { "1.2.643.7.1.2.1.2.1", NULL };
 static const char *asn1_w512_psb_n[] =    { "id-tc26-gost-3410-2012-512-paramSetB", NULL };
 static const char *asn1_w512_psb_i[] =    { "1.2.643.7.1.2.1.2.2", NULL };
 static const char *asn1_w512_psc_n[] =    { "id-tc26-gost-3410-2012-512-paramSetC", NULL };
 static const char *asn1_w512_psc_i[] =    { "1.2.643.7.1.2.1.2.3", NULL };

 static const char *asn1_blom_m_n[] =      { "blom-master", "blom-matrix", NULL };
 static const char *asn1_blom_m_i[] =      { "1.2.643.2.52.1.181.1", NULL };
 static const char *asn1_blom_a_n[] =      { "blom-abonent", "blom-user", NULL };
 static const char *asn1_blom_a_i[] =      { "1.2.643.2.52.1.181.2", NULL };
 static const char *asn1_blom_p_n[] =      { "blom-pairwise", NULL };
 static const char *asn1_blom_p_i[] =      { "1.2.643.2.52.1.181.3", NULL };

 static const char *asn1_akcont_n[] =      { "libakrypt-container", NULL };
 static const char *asn1_akcont_i[] =      { "1.2.643.2.52.1.127.1.1", NULL };

 static const char *asn1_nokey_n[] =       { "no-basic-key", NULL };
 static const char *asn1_nokey_i[] =       { "1.2.643.2.52.1.127.2.0", NULL };
 static const char *asn1_pbkdf2key_n[] =   { "pbkdf2-basic-key", NULL };
 static const char *asn1_pbkdf2key_i[] =   { "1.2.643.2.52.1.127.2.1", NULL };
 static const char *asn1_sdhkey_n[] =      { "static-dh-basic-key", NULL };
 static const char *asn1_sdhkey_i[] =      { "1.2.643.2.52.1.127.2.2", NULL };
 static const char *asn1_extkey_n[] =      { "external-basic-key", NULL };
 static const char *asn1_extkey_i[] =      { "1.2.643.2.52.1.127.2.3", NULL };

 static const char *asn1_symkmd_n[] =      { "symmetric-key-content", NULL };
 static const char *asn1_symkmd_i[] =      { "1.2.643.2.52.1.127.3.1", NULL };
 static const char *asn1_skmd_n[] =        { "secret-key-content", NULL };
 static const char *asn1_skmd_i[] =        { "1.2.643.2.52.1.127.3.2", NULL };
 static const char *asn1_pkmd_n[] =        { "public-key-certificate-content", NULL };
 static const char *asn1_pkmd_i[] =        { "1.2.643.2.52.1.127.3.3", NULL };
 static const char *asn1_pkmdr_n[] =       { "public-key-request-content", NULL };
 static const char *asn1_pkmdr_i[] =       { "1.2.643.2.52.1.127.3.4", NULL };
 static const char *asn1_ecmd_n[] =        { "encrypted-content", NULL };
 static const char *asn1_ecmd_i[] =        { "1.2.643.2.52.1.127.3.5", NULL };
 static const char *asn1_pcmd_n[] =        { "plain-content", NULL };
 static const char *asn1_pcmd_i[] =        { "1.2.643.2.52.1.127.3.6", NULL };

/* добавляем аттрибуты типов (X.500) и расширенные аттрибуты */
 static const char *asn1_email_n[] =       { "email-address", "em", "email", NULL };
 static const char *asn1_email_i[] =       { "1.2.840.113549.1.9.1", NULL };
 static const char *asn1_cn_n[] =          { "common-name", "cn", NULL };
 static const char *asn1_cn_i[] =          { "2.5.4.3", NULL };
 static const char *asn1_s_n[] =           { "surname", "su", NULL };
 static const char *asn1_s_i[] =           { "2.5.4.4", NULL };
 static const char *asn1_sn_n[] =          { "serial-number", "sn", NULL };
 static const char *asn1_sn_i[] =          { "2.5.4.5", NULL };
 static const char *asn1_c_n[] =           { "country-name", "ct", NULL };
 static const char *asn1_c_i[] =           { "2.5.4.6", NULL };
 static const char *asn1_l_n[] =           { "locality-name", "ln", NULL };
 static const char *asn1_l_i[] =           { "2.5.4.7", NULL };
 static const char *asn1_st_n[] =          { "state-or-province-name", "st", NULL };
 static const char *asn1_st_i[] =          { "2.5.4.8", NULL };
 static const char *asn1_sa_n[] =          { "street-address", "sa", NULL };
 static const char *asn1_sa_i[] =          { "2.5.4.9", NULL };
 static const char *asn1_o_n[] =           { "organization", "or", NULL };
 static const char *asn1_o_i[] =           { "2.5.4.10", NULL };
 static const char *asn1_ou_n[] =          { "organization-unit", "ou", NULL };
 static const char *asn1_ou_i[] =          { "2.5.4.11", NULL };

 static const char *asn1_ku_n[] =          { "key-usage", NULL };
 static const char *asn1_ku_i[] =          { "2.5.29.15", NULL };
 static const char *asn1_ski_n[] =         { "subject-key-identifier", NULL };
 static const char *asn1_ski_i[] =         { "2.5.29.14", NULL };
 static const char *asn1_bc_n[] =          { "basic-constraints", NULL };
 static const char *asn1_bc_i[] =          { "2.5.29.19", NULL };
 static const char *asn1_crldp_n[] =       { "crl-distribution-points", NULL };
 static const char *asn1_crldp_i[] =       { "2.5.29.31", NULL };
 static const char *asn1_cp_n[] =          { "certificate-policies", NULL };
 static const char *asn1_cp_i[] =          { "2.5.29.32", NULL };
 static const char *asn1_wcp_n[] =         { "wildcard-certificate-policy", NULL };
 static const char *asn1_wcp_i[] =         { "2.5.29.32.0", NULL };
 static const char *asn1_aki_n[] =         { "authority-key-identifier", NULL };
 static const char *asn1_aki_i[] =         { "2.5.29.35", NULL };
 static const char *asn1_eku_n[] =         { "extended-key-usage", NULL };
 static const char *asn1_eku_i[] =         { "2.5.29.37", NULL };

/* значения для extended key usage */
 static const char *asn1_kpsa_n[] =        { "tls-server-authentication", NULL };
 static const char *asn1_kpsa_i[] =        { "1.3.6.1.5.5.7.3.1", NULL };
 static const char *asn1_kpca_n[] =        { "tls-client-authentication", NULL };
 static const char *asn1_kpca_i[] =        { "1.3.6.1.5.5.7.3.2", NULL };
 static const char *asn1_kpcs_n[] =        { "executable-code-signing", NULL };
 static const char *asn1_kpcs_i[] =        { "1.3.6.1.5.5.7.3.3", NULL };
 static const char *asn1_kpep_n[] =        { "email-protection", NULL };
 static const char *asn1_kpep_i[] =        { "1.3.6.1.5.5.7.3.4", NULL };

/* это добро из Приказа ФСБ N 795 */
 static const char *asn1_ogrn_n[] =        { "ogrn", NULL };
 static const char *asn1_ogrn_i[] =        { "1.2.643.100.1", NULL };
 static const char *asn1_snils_n[] =       { "snils", NULL };
 static const char *asn1_snils_i[] =       { "1.2.643.100.3", NULL };
 static const char *asn1_ogrnip_n[] =      { "ogrnip", NULL };
 static const char *asn1_ogrnip_i[] =      { "1.2.643.100.5", NULL };
 static const char *asn1_owner_mod_n[] =   { "subject-crypto-module", NULL };
 static const char *asn1_owner_mod_i[] =   { "1.2.643.100.111", NULL };
 static const char *asn1_issuer_mod_n[] =  { "issuer-crypto-module", NULL };
 static const char *asn1_issuer_mod_i[] =  { "1.2.643.100.112", NULL };
 static const char *asn1_inn_n[] =         { "inn", NULL };
 static const char *asn1_inn_i[] =         { "1.2.643.3.131.1.1", NULL };

 static const char *asn1_class_kc1_n[] =   { "digital-signature-module, class kc1", "kc1", NULL };
 static const char *asn1_class_kc1_i[] =   { "1.2.643.100.113.1", NULL };
 static const char *asn1_class_kc2_n[] =   { "digital-signature-module, class kc2", "kc2", NULL };
 static const char *asn1_class_kc2_i[] =   { "1.2.643.100.113.2", NULL };
 static const char *asn1_class_kc3_n[] =   { "digital-signature-module, class kc3", "kc3", NULL };
 static const char *asn1_class_kc3_i[] =   { "1.2.643.100.113.3", NULL };
 static const char *asn1_class_kb1_n[] =   { "digital-signature-module, class kb1", "kb", NULL };
 static const char *asn1_class_kb1_i[] =   { "1.2.643.100.113.4", NULL };
 static const char *asn1_class_kb2_n[] =   { "digital-signature-module, class kb2", NULL };
 static const char *asn1_class_kb2_i[] =   { "1.2.643.100.113.5", NULL };
 static const char *asn1_class_ka1_n[] =   { "digital-signature-module, class ka", "ka", NULL };
 static const char *asn1_class_ka1_i[] =   { "1.2.643.100.113.6", NULL };

/* ----------------------------------------------------------------------------------------------- */
/* вот что приходится разбирать в сертификатах от КриптоПро */
/*   Microsoft OID...................................1.3.6.1.4.1.311  */
/*   см. также https://www.dogtagpki.org/wiki/Certificate_Extensions  */
/* ----------------------------------------------------------------------------------------------- */
 static const char *asn1_mscav_n[] =       { "microsoft-ca-version", NULL };
 static const char *asn1_mscav_i[] =       { "1.3.6.1.4.1.311.21.1", NULL };
 static const char *asn1_mspsh_n[] =       { "microsoft-previous-certificate-hash", NULL };
 static const char *asn1_mspsh_i[] =       { "1.3.6.1.4.1.311.21.2", NULL };
 static const char *asn1_mstndc_n[] =      { "microsoft-enrollment-certificate-type",
                                             NULL };
 static const char *asn1_mstndc_i[] =      { "1.3.6.1.4.1.311.20.2", NULL };

/* ----------------------------------------------------------------------------------------------- */
 #define ak_object_bckey_magma { sizeof( struct bckey ), \
                           ( ak_function_create_object *) ak_bckey_create_magma, \
                           ( ak_function_destroy_object *) ak_bckey_destroy, \
                           ( ak_function_set_key_object *)ak_bckey_set_key, \
                           ( ak_function_set_key_random_object *)ak_bckey_set_key_random, \
                      ( ak_function_set_key_from_password_object *)ak_bckey_set_key_from_password }

 #define ak_object_bckey_kuznechik { sizeof( struct bckey ), \
                           ( ak_function_create_object *) ak_bckey_create_kuznechik, \
                           ( ak_function_destroy_object *) ak_bckey_destroy, \
                           ( ak_function_set_key_object *)ak_bckey_set_key, \
                           ( ak_function_set_key_random_object *)ak_bckey_set_key_random, \
                      ( ak_function_set_key_from_password_object *)ak_bckey_set_key_from_password }

 #define ak_object_bckey_serpent { sizeof( struct bckey ), \
                           ( ak_function_create_object *) ak_bckey_create_serpent, \
                           ( ak_function_destroy_object *) ak_bckey_destroy, \
                           ( ak_function_set_key_object *)ak_bckey_set_key, \
                           ( ak_function_set_key_random_object *)ak_bckey_set_key_random, \
                      ( ak_function_set_key_from_password_object *)ak_bckey_set_key_from_password }

 #define ak_object_hmac_streebog256 { sizeof( struct hmac ), \
                           ( ak_function_create_object *) ak_hmac_create_streebog256, \
                           ( ak_function_destroy_object *) ak_hmac_destroy, \
                           ( ak_function_set_key_object *)ak_hmac_set_key, \
                           ( ak_function_set_key_random_object *)ak_hmac_set_key_random, \
                       ( ak_function_set_key_from_password_object *)ak_hmac_set_key_from_password }

 #define ak_object_hmac_streebog512 { sizeof( struct hmac ), \
                           ( ak_function_create_object *) ak_hmac_create_streebog512, \
                           ( ak_function_destroy_object *) ak_hmac_destroy, \
                           ( ak_function_set_key_object *)ak_hmac_set_key, \
                           ( ak_function_set_key_random_object *)ak_hmac_set_key_random, \
                       ( ak_function_set_key_from_password_object *)ak_hmac_set_key_from_password }

 #define ak_object_signkey256 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_signkey_create_streebog256, \
                          ( ak_function_destroy_object *) ak_signkey_destroy, \
                          ( ak_function_set_key_object *) ak_signkey_set_key, \
                          ( ak_function_set_key_random_object *) ak_signkey_set_key_random, NULL }

 #define ak_object_signkey512 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_signkey_create_streebog512, \
                          ( ak_function_destroy_object *) ak_signkey_destroy, \
                          ( ak_function_set_key_object *) ak_signkey_set_key, \
                          ( ak_function_set_key_random_object *) ak_signkey_set_key_random, NULL }

 #define ak_object_verifykey256 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_verifykey_create_streebog256, \
                          ( ak_function_destroy_object *) ak_verifykey_destroy, \
                                                                                NULL, NULL, NULL }

 #define ak_object_verifykey512 { sizeof( struct signkey ), \
                          ( ak_function_create_object *) ak_verifykey_create_streebog512, \
                          ( ak_function_destroy_object *) ak_verifykey_destroy, \
                                                                                NULL, NULL, NULL }

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
static struct oid libakrypt_oids[] =
{
 /* идентификаторы  */
 { random_generator, algorithm, asn1_lcg_i, asn1_lcg_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_lcg,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#if defined(__unix__) || defined(__APPLE__)
 { random_generator, algorithm, asn1_dev_random_i, asn1_dev_random_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_random,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
 { random_generator, algorithm, asn1_dev_urandom_i, asn1_dev_urandom_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_urandom,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#endif
#ifdef _WIN32
 { random_generator, algorithm,asn1_winrtl_i, asn1_winrtl_n, NULL,
  {{ sizeof( struct random ), (ak_function_create_object *)ak_random_create_winrtl,
                              (ak_function_destroy_object *)ak_random_destroy, NULL, NULL, NULL },
                                                                ak_object_undefined, NULL, NULL }},
#endif

/* добавляем идентификаторы алгоритмов */
 { hash_function, algorithm, asn1_streebog256_i, asn1_streebog256_n, NULL,
  {{ sizeof( struct hash ), ( ak_function_create_object *) ak_hash_create_streebog256,
                              ( ak_function_destroy_object *) ak_hash_destroy, NULL, NULL, NULL },
                              ak_object_undefined, (ak_function_run_object *) ak_hash_ptr, NULL }},

 { hash_function, algorithm, asn1_streebog512_i, asn1_streebog512_n, NULL,
  {{ sizeof( struct hash ), ( ak_function_create_object *) ak_hash_create_streebog512,
                              ( ak_function_destroy_object *) ak_hash_destroy, NULL, NULL, NULL },
                              ak_object_undefined, (ak_function_run_object *) ak_hash_ptr, NULL }},

 { hmac_function, algorithm, asn1_hmac_streebog256_i, asn1_hmac_streebog256_n, NULL,
                            { ak_object_hmac_streebog256,
                              ak_object_undefined, (ak_function_run_object *) ak_hmac_ptr, NULL }},

 { hmac_function, algorithm, asn1_hmac_streebog512_i, asn1_hmac_streebog512_n, NULL,
                            { ak_object_hmac_streebog512,
                              ak_object_undefined, (ak_function_run_object *) ak_hmac_ptr, NULL }},

 { block_cipher, algorithm, asn1_magma_i, asn1_magma_n, NULL,
                                       { ak_object_bckey_magma, ak_object_undefined, NULL, NULL }},

 { block_cipher, algorithm, asn1_kuznechik_i, asn1_kuznechik_n, NULL,
                                   { ak_object_bckey_kuznechik, ak_object_undefined, NULL, NULL }},

 { block_cipher, algorithm, asn1_serpent_i, asn1_serpent_n, NULL,
                                    { ak_object_bckey_serpent, ak_object_undefined, NULL, NULL }},

/* базовые режимы блочного шифрования */
 { block_cipher, encrypt_mode, asn1_ctr_magma_i, asn1_ctr_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr,
                                                       ( ak_function_run_object *) ak_bckey_ctr }},

 { block_cipher, encrypt_mode, asn1_ctr_kuznechik_i, asn1_ctr_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr,
                                                       ( ak_function_run_object *) ak_bckey_ctr }},

 { block_cipher, encrypt_mode, asn1_ctr_serpent_i, asn1_ctr_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr,
      ( ak_function_run_object *) ak_bckey_ctr }},

 { block_cipher, encrypt_mode, asn1_ofb_magma_i, asn1_ofb_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ofb,
                                                       ( ak_function_run_object *) ak_bckey_ofb }},

 { block_cipher, encrypt_mode, asn1_ofb_kuznechik_i, asn1_ofb_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ofb,
                                                       ( ak_function_run_object *) ak_bckey_ofb }},

 { block_cipher, encrypt_mode, asn1_ofb_serpent_i, asn1_ofb_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ofb,
     ( ak_function_run_object *) ak_bckey_ofb }},

 { block_cipher, encrypt_mode, asn1_cfb_magma_i, asn1_cfb_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_encrypt_cfb,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cfb }},

 { block_cipher, encrypt_mode, asn1_cfb_kuznechik_i, asn1_cfb_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_encrypt_cfb,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cfb }},

 { block_cipher, encrypt_mode, asn1_cfb_serpent_i, asn1_cfb_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined,
     ( ak_function_run_object *) ak_bckey_encrypt_cfb,
     ( ak_function_run_object *) ak_bckey_decrypt_cfb }},

 { block_cipher, encrypt_mode, asn1_cbc_magma_i, asn1_cbc_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_encrypt_cbc,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cbc }},

 { block_cipher, encrypt_mode, asn1_cbc_kuznechik_i, asn1_cbc_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_encrypt_cbc,
                                               ( ak_function_run_object *) ak_bckey_decrypt_cbc }},

 { block_cipher, encrypt_mode, asn1_cbc_serpent_i, asn1_cbc_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined,
     ( ak_function_run_object *) ak_bckey_encrypt_cbc,
     ( ak_function_run_object *) ak_bckey_decrypt_cbc }},

 { block_cipher, encrypt2k_mode, asn1_xts_magma_i, asn1_xts_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                                ( ak_function_run_object *) ak_bckey_encrypt_xts,
                                               ( ak_function_run_object *) ak_bckey_decrypt_xts }},

 { block_cipher, encrypt2k_mode, asn1_xts_kuznechik_i, asn1_xts_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                                 ( ak_function_run_object *) ak_bckey_encrypt_xts,
                                               ( ak_function_run_object *) ak_bckey_decrypt_xts }},

 { block_cipher, encrypt2k_mode, asn1_xts_serpent_i, asn1_xts_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_bckey_serpent,
     ( ak_function_run_object *) ak_bckey_encrypt_xts,
     ( ak_function_run_object *) ak_bckey_decrypt_xts }},

 { block_cipher, acpkm, asn1_acpkm_magma_i, asn1_acpkm_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_ctr_acpkm,
                                                 ( ak_function_run_object *) ak_bckey_ctr_acpkm }},

 { block_cipher, acpkm, asn1_acpkm_kuznechik_i, asn1_acpkm_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                  ( ak_function_run_object *) ak_bckey_ctr_acpkm,
                                                 ( ak_function_run_object *) ak_bckey_ctr_acpkm }},

 { block_cipher, acpkm, asn1_acpkm_serpent_i, asn1_acpkm_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined,
     ( ak_function_run_object *) ak_bckey_ctr_acpkm,
     ( ak_function_run_object *) ak_bckey_ctr_acpkm }},

 { block_cipher, mac, asn1_cmac_magma_i, asn1_cmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_undefined, ( ak_function_run_object *) ak_bckey_cmac, NULL }},

 { block_cipher, mac, asn1_cmac_kuznechik_i, asn1_cmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_undefined,
                                                ( ak_function_run_object *) ak_bckey_cmac, NULL }},

 { block_cipher, mac, asn1_cmac_serpent_i, asn1_cmac_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_undefined,
     ( ak_function_run_object *) ak_bckey_cmac, NULL }},

/* расширенные режимы блочного шифрования */
 { block_cipher, aead, asn1_mgm_magma_i, asn1_mgm_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                               ( ak_function_run_object *) ak_bckey_encrypt_mgm,
                                               ( ak_function_run_object *) ak_bckey_decrypt_mgm }},

 { block_cipher, aead, asn1_mgm_kuznechik_i, asn1_mgm_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                               ( ak_function_run_object *) ak_bckey_encrypt_mgm,
                                               ( ak_function_run_object *) ak_bckey_decrypt_mgm }},

 { block_cipher, aead, asn1_mgm_serpent_i, asn1_mgm_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_bckey_serpent,
     ( ak_function_run_object *) ak_bckey_encrypt_mgm,
     ( ak_function_run_object *) ak_bckey_decrypt_mgm }},

 { block_cipher, aead, asn1_ctr_cmac_magma_i, asn1_ctr_cmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_cmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_cmac }},

 { block_cipher, aead, asn1_ctr_cmac_kuznechik_i, asn1_ctr_cmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_cmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_cmac }},

 { block_cipher, aead, asn1_ctr_cmac_serpent_i, asn1_ctr_cmac_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_bckey_serpent,
     ( ak_function_run_object *) ak_bckey_encrypt_ctr_cmac,
     ( ak_function_run_object *) ak_bckey_decrypt_ctr_cmac }},

 { block_cipher, aead, asn1_ctr_hmac_magma_streebog256_i, asn1_ctr_hmac_magma_streebog256_n, NULL,
  { ak_object_bckey_magma, ak_object_hmac_streebog256,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead, asn1_ctr_hmac_magma_streebog512_i, asn1_ctr_hmac_magma_streebog512_n, NULL,
  { ak_object_bckey_magma, ak_object_hmac_streebog512,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
             asn1_ctr_hmac_kuznechik_streebog256_i, asn1_ctr_hmac_kuznechik_streebog256_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_hmac_streebog256,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
             asn1_ctr_hmac_kuznechik_streebog512_i, asn1_ctr_hmac_kuznechik_streebog512_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_hmac_streebog512,
                                          ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
                                          ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
   asn1_ctr_hmac_serpent_streebog256_i, asn1_ctr_hmac_serpent_streebog256_n, NULL,
   { ak_object_bckey_serpent, ak_object_hmac_streebog256,
     ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
     ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead,
   asn1_ctr_hmac_serpent_streebog512_i, asn1_ctr_hmac_serpent_streebog512_n, NULL,
   { ak_object_bckey_serpent, ak_object_hmac_streebog512,
     ( ak_function_run_object *) ak_bckey_encrypt_ctr_hmac,
     ( ak_function_run_object *) ak_bckey_decrypt_ctr_hmac }},

 { block_cipher, aead, asn1_xtsmac_magma_i, asn1_xtsmac_magma_n, NULL,
  { ak_object_bckey_magma, ak_object_bckey_magma,
                                            ( ak_function_run_object *) ak_bckey_encrypt_xtsmac,
                                            ( ak_function_run_object *) ak_bckey_decrypt_xtsmac }},

 { block_cipher, aead, asn1_xtsmac_kuznechik_i, asn1_xtsmac_kuznechik_n, NULL,
  { ak_object_bckey_kuznechik, ak_object_bckey_kuznechik,
                                            ( ak_function_run_object *) ak_bckey_encrypt_xtsmac,
                                            ( ak_function_run_object *) ak_bckey_decrypt_xtsmac }},

 { block_cipher, aead, asn1_xtsmac_serpent_i, asn1_xtsmac_serpent_n, NULL,
   { ak_object_bckey_serpent, ak_object_bckey_serpent,
     ( ak_function_run_object *) ak_bckey_encrypt_xtsmac,
     ( ak_function_run_object *) ak_bckey_decrypt_xtsmac }},

 { sign_function, algorithm, asn1_sign256_i, asn1_sign256_n, NULL,
  { ak_object_signkey256, ak_object_undefined,
                                          ( ak_function_run_object *) ak_signkey_sign_ptr, NULL }},

 { sign_function, algorithm, asn1_sign512_i, asn1_sign512_n, NULL,
  { ak_object_signkey512, ak_object_undefined,
                                          ( ak_function_run_object *) ak_signkey_sign_ptr, NULL }},

 { verify_function, algorithm, asn1_verify256_i, asn1_verify256_n, NULL,
  { ak_object_verifykey256, ak_object_undefined,
                                      ( ak_function_run_object *) ak_verifykey_verify_ptr, NULL }},

 { verify_function, algorithm, asn1_verify512_i, asn1_verify512_n, NULL,
  { ak_object_verifykey256, ak_object_undefined,
                                      ( ak_function_run_object *) ak_verifykey_verify_ptr, NULL }},

 { identifier, wcurve_params, asn1_w256_pst_i, asn1_w256_pst_n,
          (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetTest, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psa_i, asn1_w256_psa_n,
             (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psb_i, asn1_w256_psb_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psc_i, asn1_w256_psc_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_psd_i, asn1_w256_psd_n,
              (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w256_axel_i, asn1_w256_axel_n,
           (ak_pointer) &id_axel_gost_3410_2012_256_paramSet_N0, ak_functional_objects_undefined },

 { identifier, wcurve_params, asn1_w512_pst_i, asn1_w512_pst_n,
          (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetTest, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psa_i, asn1_w512_psa_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetA, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psb_i, asn1_w512_psb_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetB, ak_functional_objects_undefined },
 { identifier, wcurve_params, asn1_w512_psc_i, asn1_w512_psc_n,
             (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetC, ak_functional_objects_undefined },

/* идентификаторы, используемые при реализации схемы Блома */
 { blom_master, algorithm, asn1_blom_m_i, asn1_blom_m_n, NULL, ak_functional_objects_undefined },
 { blom_abonent, algorithm, asn1_blom_a_i, asn1_blom_a_n, NULL, ak_functional_objects_undefined },
 { blom_pairwise, algorithm, asn1_blom_p_i, asn1_blom_p_n, NULL, ak_functional_objects_undefined },

/* идентификаторы, используемые при разборе сертификатов и ключевых контейнеров */
 { identifier, descriptor, asn1_akcont_i, asn1_akcont_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_nokey_i, asn1_nokey_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_pbkdf2key_i, asn1_pbkdf2key_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sdhkey_i, asn1_sdhkey_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_extkey_i, asn1_extkey_n, NULL, ak_functional_objects_undefined },

 { identifier, parameter, asn1_symkmd_i, asn1_symkmd_n,
                             (ak_pointer) symmetric_key_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_skmd_i, asn1_skmd_n,
                                (ak_pointer) secret_key_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pkmd_i, asn1_pkmd_n,
                    (ak_pointer) public_key_certificate_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pkmdr_i, asn1_pkmdr_n,
                        (ak_pointer) public_key_request_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_ecmd_i, asn1_ecmd_n,
                                 (ak_pointer) encrypted_content, ak_functional_objects_undefined },
 { identifier, parameter, asn1_pcmd_i, asn1_pcmd_n,
                                     (ak_pointer) plain_content, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_email_i, asn1_email_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cn_i, asn1_cn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_s_i, asn1_s_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sn_i, asn1_sn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_c_i, asn1_c_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_l_i, asn1_l_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_st_i, asn1_st_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_sa_i, asn1_sa_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_o_i, asn1_o_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ou_i, asn1_ou_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_ski_i, asn1_ski_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ku_i, asn1_ku_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_bc_i, asn1_bc_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_crldp_i, asn1_crldp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_cp_i, asn1_cp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_wcp_i, asn1_wcp_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_aki_i, asn1_aki_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_eku_i, asn1_eku_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpsa_i, asn1_kpsa_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpca_i, asn1_kpca_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpcs_i, asn1_kpcs_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_kpep_i, asn1_kpep_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_ogrn_i, asn1_ogrn_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_snils_i, asn1_snils_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_ogrnip_i, asn1_ogrnip_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_owner_mod_i, asn1_owner_mod_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_issuer_mod_i, asn1_issuer_mod_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_inn_i, asn1_inn_n, NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_class_kc1_i, asn1_class_kc1_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kc2_i, asn1_class_kc2_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kc3_i, asn1_class_kc3_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kb1_i, asn1_class_kb1_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_kb2_i, asn1_class_kb2_n,
                                                           NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_class_ka1_i, asn1_class_ka1_n,
                                                           NULL, ak_functional_objects_undefined },

 { identifier, descriptor, asn1_mscav_i, asn1_mscav_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_mspsh_i, asn1_mspsh_n, NULL, ak_functional_objects_undefined },
 { identifier, descriptor, asn1_mstndc_i, asn1_mstndc_n, NULL, ak_functional_objects_undefined },

 /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
  ak_oid_undefined
};

/* ----------------------------------------------------------------------------------------------- */
/*! \param engine Тип криптографического механизма.
    \return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_engine_name( const oid_engines_t engine )
{
  if( engine > undefined_engine ) {
    ak_error_message_fmt( ak_error_oid_engine, __func__, "incorrect value of engine: %d", engine );
    return ak_null_string;
  }
 return libakrypt_engine_names[engine];
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param mode Режим криптографического механизма.
    \return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_mode_name( const oid_modes_t mode )
{
  if( mode > undefined_mode ) {
    ak_error_message_fmt( ak_error_oid_mode, __func__, "incorrect value of engine mode: %d", mode );
    return ak_null_string;
  }
 return libakrypt_mode_names[mode];
}

/* ----------------------------------------------------------------------------------------------- */
/*                           функции для создания объектов по oid                                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор создаваемого объекта
    \return Функция возвращает указатель на контекст созданного объекта. В случае возникновения
    ошибки возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_new_object( ak_oid oid )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.first.create == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                           "create an object that does not support this feature" );
    return NULL;
  }
  if( oid->func.first.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                        "create an object that does not support destroy feature" );
    return NULL;
  }

  if(( ctx = malloc( oid->func.first.size )) != NULL ) {
    if(( error = ((ak_function_create_object*)oid->func.first.create )( ctx )) != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, "creation of the %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
      if( ctx != NULL ) {
        free( ctx );
        ctx = NULL;
      }
    }
  } else
    ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );

 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор создаваемого объекта
    \return Функция возвращает указатель на контекст созданного объекта. В случае возникновения
    ошибки возвращается NULL. */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_new_second_object( ak_oid oid )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.second.create == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                           "create an object that does not support this feature" );
    return NULL;
  }
  if( oid->func.second.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                        "create an object that does not support destroy feature" );
    return NULL;
  }

  if(( ctx = malloc( oid->func.second.size )) != NULL ) {
    if(( error = ((ak_function_create_object*)oid->func.second.create )( ctx )) != ak_error_ok ) {
      ak_error_message_fmt( error, __func__, "creation of the %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
      if( ctx != NULL ) {
        free( ctx );
        ctx = NULL;
      }
    }
  } else
    ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error" );

 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор удаляемого объекта
    \param ctx Контекст удаляемого объекта
    \return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete_object( ak_oid oid, ak_pointer ctx )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ctx;
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.first.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                          "destroy an object that does not support this feature" );
  } else {
     if(( error = ((ak_function_destroy_object*)oid->func.first.destroy )( ctx )) != ak_error_ok )
       ak_error_message_fmt( error, __func__, "the destroing of %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
     }
  if( ctx != NULL ) free( ctx );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param oid Идентификатор удаляемого объекта
    \param ctx Контекст удаляемого объекта
    \return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete_second_object( ak_oid oid, ak_pointer ctx )
{
  int error = ak_error_ok;

  if( ctx == NULL ) return ctx;
  if( oid == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to object identifer" );
    return NULL;
  }
  if( oid->func.second.destroy == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                          "destroy an object that does not support this feature" );
  } else {
     if(( error = ((ak_function_destroy_object*)oid->func.second.destroy )( ctx )) != ak_error_ok )
       ak_error_message_fmt( error, __func__, "the destroing of %s object failed",
                                                      ak_libakrypt_get_engine_name( oid->engine ));
     }
  if( ctx != NULL ) free( ctx );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param index индекс oid, данное значение не должно превышать величины,
    возвращаемой функцией ak_libakrypt_oids_count().
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_index( const size_t index )
{
  if( index < ak_libakrypt_oids_count()) return &libakrypt_oids[index];
  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьное (человекочитаемое) имя криптографического механизма
    или параметра.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_name( const char *name )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     const char *str = NULL;
     size_t len = 0, jdx = 0;
     while(( str = libakrypt_oids[idx].name[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( name ) == len ) && ak_ptr_is_equal( name, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id строка, содержащая символьную запись идентификатора - последовательность чисел,
    разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_id( const char *id )
{
  size_t idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     const char *str = NULL;
     size_t len = 0, jdx = 0;
     while(( str = libakrypt_oids[idx].id[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( id ) == len ) && ak_ptr_is_equal( id, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ni строка, содержащая символьную запись имени или идентификатора - последовательности
    чисел, разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_ni( const char *ni )
{
  size_t idx = 0;
  if( ni == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
              "using null pointer to oid name or identifier" );
    return NULL;
  }

  /* перебор по всем возможным значениям имен */
  do{
    const char *str = NULL;
    size_t len = 0, jdx = 0;
    while(( str = libakrypt_oids[idx].name[jdx] ) != NULL ) {
      len = strlen( str );
      if(( strlen( ni ) == len ) && ak_ptr_is_equal( ni, str, len ))
        return  &libakrypt_oids[idx];
      jdx++;
    }
  } while( ++idx < ak_libakrypt_oids_count( ));

  /* перебор по всем возможным значениям идентификаторов */
  idx = 0;
  do{
    const char *str = NULL;
    size_t len = 0, jdx = 0;
    while(( str = libakrypt_oids[idx].id[jdx] ) != NULL ) {
      len = strlen( str );
      if(( strlen( ni ) == len ) && ak_ptr_is_equal( ni, str, len ))
        return  &libakrypt_oids[idx];
      jdx++;
    }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr указатель на область памяти, по которой ищется oid
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_data( ak_const_pointer ptr )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }

 /* перебор по всем возможным значениям */
  do{
     if( libakrypt_oids[idx].data == ptr ) return  &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_engine( const oid_engines_t engine )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].engine == engine ) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_engine, __func__, "searching oid with wrong engine" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим работы криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_find_by_mode( const oid_modes_t mode )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].mode == mode ) return &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_mode, __func__, "searching oid with wrong mode" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_findnext_by_engine( const ak_oid startoid, const oid_engines_t engine )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
    if( oid->engine == engine ) return oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param mode режим использования криптографического механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_findnext_by_mode( const ak_oid startoid, const oid_modes_t mode )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->mode != undefined_mode ) {
    if( oid->mode == mode ) return oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid Тестируемый на корректность адрес
    @return Функция возвращает истину, если заданный адрес `oid` дествительно содержится
    среди предопределенных oid библиотеки (является корректно определенным адресом).               */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_oid_check( const ak_pointer ptr )
{
  size_t i;
  bool_t result = ak_false;

  for( i = 0; i < ak_libakrypt_oids_count(); i++ )
     if( ptr == &libakrypt_oids[i] ) result = ak_true;

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
