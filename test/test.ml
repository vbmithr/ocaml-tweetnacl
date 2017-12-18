open Tweetnacl

let sha512 () =
  let msg = "Voulez-vous coucher avec moi, ce soir ?" |> Cstruct.of_string in
  let resp = `Hex "7941f442d956f124d77ee1d1f0ba3db100751090462cdce4aed5fcd240529097bc666bf9c424becde760910df652c7aefec50b02d7f6efe666f79e5242fb755b" in
  let digest = Sha512.digest msg in
  assert (resp = (Hex.of_cstruct digest))

let basic = [
  "sha512", `Quick, sha512 ;
]

let () =
  Alcotest.run "tweetnacl" [
    "basic", basic ;
  ]
