module Rand = struct
  external randombytes : Cstruct.buffer -> int -> unit =
    "ml_randombytes" [@@noalloc]

  let gen sz =
    let cs = Cstruct.create_unsafe sz in
    randombytes (Cstruct.to_bigarray cs) sz ;
    cs

  let write cs =
    Cstruct.(randombytes (to_bigarray cs) (len cs))
end

module Hash = struct
  let bytes = 64

  external sha512 :
    Cstruct.buffer -> Cstruct.buffer -> int -> unit =
    "ml_crypto_hash" [@@noalloc]

  let sha512 msg =
    let q = Cstruct.create_unsafe bytes in
    sha512 q.buffer msg.Cstruct.buffer (Cstruct.len msg) ;
    q
end

module Sign = struct
  type secret
  type extended
  type public

  let bytes = 64
  let pkbytes = 32
  let skbytes = 64

  type _ key =
    | Sk : Cstruct.t -> secret key
    | Ek : Cstruct.t -> extended key
    | Pk : Cstruct.t -> public key

  let sk_of_cstruct cs = Sk (Cstruct.sub cs 0 skbytes)
  let ek_of_cstruct cs = Ek (Cstruct.sub cs 0 skbytes)
  let pk_of_cstruct cs = Pk (Cstruct.sub cs 0 pkbytes)

  let to_cstruct : type a. a key -> Cstruct.t = function
    | Pk cs -> cs
    | Sk cs -> cs
    | Ek cs -> cs

  let pp : type a. Format.formatter -> a key -> unit = fun ppf -> function
    | Pk cs -> Format.fprintf ppf "P %a" Hex.pp (Hex.of_cstruct cs)
    | Sk cs -> Format.fprintf ppf "S %a" Hex.pp (Hex.of_cstruct cs)
    | Ek cs -> Format.fprintf ppf "E %a" Hex.pp (Hex.of_cstruct cs)

  let show t = Format.asprintf "%a" pp t

  let equal :
    type a. a key -> a key -> bool = fun a b -> match a, b with
    | Pk a, Pk b -> Cstruct.equal a b
    | Sk a, Sk b -> Cstruct.equal a b
    | Ek a, Ek b -> Cstruct.equal a b

  external keypair :
    Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_crypto_sign_keypair" [@@noalloc]

  external keypair_seed :
    Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_crypto_sign_keypair_seed" [@@noalloc]

  let keypair ?seed () =
    let pk = Cstruct.create_unsafe pkbytes in
    let sk = Cstruct.create_unsafe skbytes in
    begin match seed with
      | None ->
        Cstruct.(keypair (to_bigarray pk) (to_bigarray sk))
      | Some cs ->
        Cstruct.blit cs 0 sk 0 pkbytes ;
        Cstruct.(keypair_seed (to_bigarray pk) (to_bigarray sk))
    end ;
    Pk pk, Sk sk

  let extended (Sk sk) =
    let cs = Hash.sha512 (Cstruct.sub sk 0 pkbytes) in
    Cstruct.(set_uint8 cs 0 (get_uint8 cs 0 land 248)) ;
    Cstruct.(set_uint8 cs 31 (get_uint8 cs 31 land 127)) ;
    Cstruct.(set_uint8 cs 31 (get_uint8 cs 31 lor 64)) ;
    Ek cs

  external sign :
    Cstruct.buffer -> Cstruct.buffer -> int =
    "ml_crypto_sign" [@@noalloc]

  external sign_extended :
    Cstruct.buffer -> Cstruct.buffer -> int =
    "ml_crypto_sign_extended" [@@noalloc]

  let sign ~key:(Sk sk) msg =
    let msglen = Cstruct.len msg in
    let cs = Cstruct.create_unsafe (bytes + msglen) in
    Cstruct.blit msg 0 cs bytes msglen ;
    let _len = Cstruct.(sign (to_bigarray cs) (to_bigarray sk)) in
    cs

  let sign_extended ~key:(Ek ek) msg =
    let msglen = Cstruct.len msg in
    let cs = Cstruct.create_unsafe (bytes + msglen) in
    Cstruct.blit msg 0 cs bytes msglen ;
    let _len = Cstruct.(sign_extended (to_bigarray cs) (to_bigarray ek)) in
    cs

  let detached ~key msg =
    Cstruct.sub (sign ~key msg) 0 bytes

  let detached_extended ~key msg =
    Cstruct.sub (sign_extended ~key msg) 0 bytes

  external verify :
    Cstruct.buffer -> Cstruct.buffer -> Cstruct.buffer -> Cstruct.buffer -> int =
    "ml_crypto_sign_open" [@@noalloc]

  let verify ~key:(Pk pk) smsg =
    let mlen = Cstruct.create_unsafe 8 in
    let msg = Cstruct.(create (len smsg)) in
    let ret = Cstruct.(verify
               (to_bigarray msg) (to_bigarray mlen)
               (to_bigarray smsg) (to_bigarray pk)) in
    match ret with
    | 0 ->
      let len = Cstruct.LE.get_uint64 mlen 0 |> Int64.to_int in
      Some (Cstruct.sub msg 0 len)
    | _ -> None

  let verify_detached ~key ~signature msg =
    let cs = Cstruct.create_unsafe (bytes + Cstruct.len msg) in
    Cstruct.blit signature 0 cs 0 bytes ;
    Cstruct.blit msg 0 cs bytes (Cstruct.len msg) ;
    match verify ~key cs with
    | None -> false
    | Some _ -> true

  external add :
    Cstruct.buffer -> Cstruct.buffer -> Cstruct.buffer -> bool =
    "ml_add" [@@noalloc]

  let add (Pk p) (Pk q) =
    let cs = Cstruct.create_unsafe pkbytes in
    Cstruct.blit p 0 cs 0 pkbytes ;
    if not Cstruct.(add (to_bigarray cs) (to_bigarray p) (to_bigarray q)) then
      invalid_arg "Sign.add: invalid points" ;
    Pk cs

  external mult :
    Cstruct.buffer -> Cstruct.buffer -> Cstruct.buffer -> bool =
    "ml_scalarmult" [@@noalloc]

  external base :
    Cstruct.buffer -> Cstruct.buffer -> bool =
    "ml_scalarbase" [@@noalloc]

  let cs_of_z z =
    let cs = Cstruct.create pkbytes in
    let bits = Z.to_bits z in
    Cstruct.blit_from_string bits 0 cs 0 (String.length bits) ;
    cs

  let mult (Pk q) s =
    let cs = Cstruct.create_unsafe pkbytes in
    let s = cs_of_z s in
    if not Cstruct.(mult (to_bigarray cs) (to_bigarray q) (to_bigarray s)) then
      invalid_arg "Sign.mult: scalar is Z.zero or point is not on the curve" ;
    Pk cs

  let base_direct s =
    let cs = Cstruct.create_unsafe pkbytes in
    if not Cstruct.(base (to_bigarray cs) (to_bigarray s)) then
      invalid_arg "Sign.base: argument should not be Z.zero" ;
    cs

  let base s =
    let cs = Cstruct.create_unsafe pkbytes in
    let scalar = cs_of_z s in
    if not Cstruct.(base (to_bigarray cs) (to_bigarray scalar)) then
      invalid_arg "Sign.base: argument should not be Z.zero" ;
    Pk cs

  let public : type a. a key -> public key = function
    | Pk _ as pk -> pk
    | Sk cs -> Pk (Cstruct.sub cs 32 32)
    | Ek cs -> Pk (base_direct (Cstruct.sub cs 0 32))
end
