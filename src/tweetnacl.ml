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
  type public
  type extended

  let bytes = 64
  let pkbytes = 32
  let skbytes = 64

  type _ key =
    | Pk : Cstruct.t -> public key
    | Sk : Cstruct.t -> secret key
    | Ek : Cstruct.t -> extended key

  let to_cstruct : type a. a key -> Cstruct.t = function
    | Pk cs -> cs
    | Sk cs -> cs
    | Ek cs -> cs

  external keypair :
    Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_crypto_sign_keypair" [@@noalloc]

  let keypair () =
    let pk = Cstruct.create_unsafe pkbytes in
    let sk = Cstruct.create_unsafe skbytes in
    Cstruct.(keypair (to_bigarray pk) (to_bigarray sk)) ;
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
    Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_add" [@@noalloc]

  let add (Pk p) (Pk q) =
    let cs = Cstruct.create_unsafe pkbytes in
    Cstruct.blit p 0 cs 0 pkbytes ;
    Cstruct.(add (to_bigarray cs) (to_bigarray q)) ;
    Pk cs

  external mult :
    Cstruct.buffer -> Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_scalarmult" [@@noalloc]

  external base :
    Cstruct.buffer -> Cstruct.buffer -> unit =
    "ml_scalarbase" [@@noalloc]

  let cs_of_z z =
    let cs = Cstruct.create pkbytes in
    let bits = Z.to_bits z in
    Cstruct.blit_from_string bits 0 cs 0 (String.length bits) ;
    cs

  let mult (Pk q) s =
    let cs = Cstruct.create_unsafe pkbytes in
    let s = cs_of_z s in
    Cstruct.(mult (to_bigarray cs) (to_bigarray q) (to_bigarray s)) ;
    Pk cs

  let base_direct s =
    let cs = Cstruct.create_unsafe pkbytes in
    Cstruct.(base (to_bigarray cs) (to_bigarray s)) ;
    cs

  let base s =
    let cs = Cstruct.create_unsafe pkbytes in
    let scalar = cs_of_z s in
    Cstruct.(base (to_bigarray cs) (to_bigarray scalar)) ;
    Pk cs

  let public : type a. a key -> public key = function
    | Pk _ as pk -> pk
    | Sk cs -> Pk (Cstruct.sub cs 32 32)
    | Ek cs -> Pk (base_direct (Cstruct.sub cs 0 32))
end
