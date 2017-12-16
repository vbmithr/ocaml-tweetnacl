module Auth = struct
  let primitive = "hmacsha512256"
  let version = "-"
  let implementation = "crypto_auth/hmacsha512256/tweet"
  let bytes = 32
  let keybytes = 32
end

module Scalarmult = struct
  let primitive = "curve25519"
  let version = "-"
  let implementation = "crypto_scalarmult/curve25519/tweet"
  let bytes = 32
  let scalarbytes = 32
end
