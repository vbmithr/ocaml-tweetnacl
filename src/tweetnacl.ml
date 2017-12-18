module Sha512 = struct
  let bytes = 64

  external sha512 : Cstruct.buffer -> Cstruct.buffer -> int -> unit =
    "ml_crypto_hash_sha512_tweet" [@@noalloc]

  let digest msg =
    let q = Cstruct.create_unsafe bytes in
    sha512 q.buffer msg.Cstruct.buffer (Cstruct.len msg) ;
    q
end
