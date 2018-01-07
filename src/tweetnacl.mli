module Rand : sig
  val gen : int -> Cstruct.t
  val write : Cstruct.t -> unit
end

module Hash : sig
  val sha512 : Cstruct.t -> Cstruct.t
end

module Box : sig
  type secret
  type public
  type combined
  type nonce

  type _ key

  val skbytes : int
  val pkbytes : int
  val beforenmbytes : int
  val noncebytes : int
  val zerobytes : int
  val boxzerobytes : int

  val keypair : unit -> public key * secret key
  val equal : 'a key -> 'a key -> bool

  val gen_nonce : unit -> nonce
  val nonce_of_cstruct : Cstruct.t -> nonce

  val box :
    pk:public key -> sk:secret key -> nonce:nonce ->
    msg:Cstruct.t -> Cstruct.t
  val box_open :
    pk:public key -> sk:secret key -> nonce:nonce ->
    cmsg:Cstruct.t -> Cstruct.t option

  val combine : public key -> secret key -> combined key
  val box_combined :
    k:combined key -> nonce:nonce -> msg:Cstruct.t -> Cstruct.t
  val box_open_combined :
    k:combined key -> nonce:nonce -> cmsg:Cstruct.t -> Cstruct.t option
end

module Sign : sig
  type secret
  type extended
  type public
  type _ key

  val bytes : int
  val pkbytes : int
  val skbytes : int

  val pp : Format.formatter -> _ key -> unit
  val show : _ key -> string
  val to_cstruct : _ key -> Cstruct.t

  val sk_of_cstruct : Cstruct.t -> secret key
  val ek_of_cstruct : Cstruct.t -> extended key
  val pk_of_cstruct : Cstruct.t -> public key

  val keypair : ?seed:Cstruct.t -> unit -> public key * secret key
  val equal : 'a key -> 'a key -> bool

  val extended : secret key -> extended key
  val public : _ key -> public key

  val sign : key:secret key -> Cstruct.t -> Cstruct.t
  val sign_extended : key:extended key -> Cstruct.t -> Cstruct.t

  val detached : key:secret key -> Cstruct.t -> Cstruct.t
  val detached_extended : key:extended key -> Cstruct.t -> Cstruct.t

  val verify : key:public key -> Cstruct.t -> Cstruct.t option
  val verify_detached : key:public key -> signature:Cstruct.t -> Cstruct.t -> bool

  val add : public key -> public key -> public key
  val mult : public key -> Z.t -> public key
  val base : Z.t -> public key
end
