#include <sodium.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>

CAMLprim value ml_randombytes(value x, value xlen) {
    randombytes_buf(Caml_ba_data_val(x), Long_val(xlen));
    return Val_unit;
}

CAMLprim value ml_secretbox(value c, value m, value n, value k) {
    crypto_secretbox(Caml_ba_data_val(c),
		     Caml_ba_data_val(m),
		     Caml_ba_array_val(m)->dim[0],
		     Caml_ba_data_val(n),
		     Caml_ba_data_val(k));
    return Val_unit;
}

CAMLprim value ml_secretbox_open(value m, value c, value n, value k) {
    return Val_int(crypto_secretbox_open(Caml_ba_data_val(m),
					 Caml_ba_data_val(c),
					 Caml_ba_array_val(c)->dim[0],
					 Caml_ba_data_val(n),
					 Caml_ba_data_val(k)));
}

CAMLprim value ml_crypto_box_keypair(value pk, value sk) {
    crypto_box_keypair(Caml_ba_data_val(pk), Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ml_crypto_box(value c, value m, value n, value pk, value sk) {
    int ret;
    ret = crypto_box(Caml_ba_data_val(c),
		     Caml_ba_data_val(m),
		     Caml_ba_array_val(m)->dim[0],
		     Caml_ba_data_val(n),
		     Caml_ba_data_val(pk),
		     Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ml_crypto_box_open(value m, value c, value n, value pk, value sk) {
    return Val_int(crypto_box_open(Caml_ba_data_val(m),
                                   Caml_ba_data_val(c),
                                   Caml_ba_array_val(c)->dim[0],
                                   Caml_ba_data_val(n),
                                   Caml_ba_data_val(pk),
                                   Caml_ba_data_val(sk)));
}

CAMLprim value ml_crypto_box_beforenm(value k, value pk, value sk) {
    int ret;
    ret = crypto_box_beforenm(Caml_ba_data_val(k),
			      Caml_ba_data_val(pk),
			      Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ml_crypto_box_afternm(value c, value m, value n, value k) {
    crypto_box_afternm(Caml_ba_data_val(c),
                       Caml_ba_data_val(m),
                       Caml_ba_array_val(m)->dim[0],
                       Caml_ba_data_val(n),
                       Caml_ba_data_val(k));
    return Val_unit;
}

CAMLprim value ml_crypto_box_open_afternm(value m, value c, value n, value k) {
    return Val_int(crypto_box_open_afternm(Caml_ba_data_val(m),
                                           Caml_ba_data_val(c),
                                           Caml_ba_array_val(c)->dim[0],
                                           Caml_ba_data_val(n),
                                           Caml_ba_data_val(k)));
}

CAMLprim value ml_crypto_sign(value sm, value sk) {
    crypto_sign(Caml_ba_data_val(sm),
                NULL,
                (unsigned char*) Caml_ba_data_val(sm) + crypto_sign_BYTES,
                Caml_ba_array_val(sm)->dim[0] - crypto_sign_BYTES,
                Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ml_crypto_sign_open(value m, value sm, value pk) {
    return Val_int(crypto_sign_open(Caml_ba_data_val(m),
                                    NULL,
                                    Caml_ba_data_val(sm),
                                    Caml_ba_array_val(sm)->dim[0],
                                    Caml_ba_data_val(pk)));
}

CAMLprim value ml_crypto_sign_keypair(value pk, value sk) {
    crypto_sign_keypair(Caml_ba_data_val(pk), Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ml_crypto_sign_keypair_seed(value pk, value sk, value seed) {
    crypto_sign_seed_keypair(Caml_ba_data_val(pk),
			     Caml_ba_data_val(sk),
			     Caml_ba_data_val(seed));
    return Val_unit;
}
