open Tweetnacl

let msg = "Voulez-vous coucher avec moi, ce soir ?" |> Cstruct.of_string
let msglen = Cstruct.len msg

let sha512 () =
  let resp = `Hex "7941f442d956f124d77ee1d1f0ba3db100751090462cdce4aed5fcd240529097bc666bf9c424becde760910df652c7aefec50b02d7f6efe666f79e5242fb755b" in
  let digest = Hash.sha512 msg in
  assert (resp = (Hex.of_cstruct digest))

let sign () =
  let pk, sk = Sign.keypair () in
  let signed_msg = Sign.sign ~key:sk msg in
  match Sign.verify ~key:pk signed_msg with
  | None -> failwith "Impossible to verify"
  | Some verified_msg ->
    assert (Hex.of_cstruct msg =
            Hex.of_cstruct (Cstruct.sub verified_msg Sign.bytes msglen))

let sign_detached () =
  let pk, sk = Sign.keypair () in
  let signature = Sign.detached ~key:sk msg in
  match Sign.verify_detached ~key:pk ~signature msg with
  | false -> failwith "Impossible to verify"
  | true -> ()

let sign_extended () =
  let pk, sk = Sign.keypair () in
  let ek = Sign.extended sk in
  let signed_msg = Sign.sign_extended ~key:ek msg in
  match Sign.verify ~key:pk signed_msg with
  | None -> failwith "Impossible to verify"
  | Some verified_msg ->
    assert (Hex.of_cstruct msg =
            Hex.of_cstruct (Cstruct.sub verified_msg Sign.bytes msglen))

let sign_extended_detached () =
  let pk, sk = Sign.keypair () in
  let ek = Sign.extended sk in
  let signature = Sign.detached_extended ~key:ek msg in
  match Sign.verify_detached ~key:pk ~signature msg with
  | false -> failwith "Impossible to verify"
  | true -> ()

let public () =
  let pk, sk = Sign.keypair () in
  let pk' = Sign.to_cstruct pk in
  let ek = Sign.extended sk in
  let ppk = Sign.(public pk |> to_cstruct) in
  let psk = Sign.(public sk |> to_cstruct) in
  let pek = Sign.(public ek |> to_cstruct) in
  assert (Cstruct.equal pk' ppk) ;
  assert (Cstruct.equal pk' psk) ;
  assert (Cstruct.equal pk' pek)

let base () =
  let pk, sk = Sign.keypair () in
  let ek = Sign.(extended sk |> to_cstruct) in
  let z = Z.of_bits Cstruct.(sub ek 0 32 |> to_string) in
  let pk' = Sign.base z in
  assert Cstruct.(Sign.(equal (to_cstruct pk) (to_cstruct pk')))

let comm () =
  let pk1, _ = Sign.keypair () in
  let pk2, _ = Sign.keypair () in
  let pk3 = Sign.add pk1 pk2 in
  let pk3' = Sign.add pk2 pk1 in
  assert Cstruct.(Sign.(equal (to_cstruct pk3) (to_cstruct pk3')))

let assoc () =
  let pk1, _ = Sign.keypair () in
  let pk2, _ = Sign.keypair () in
  let pk3, _ = Sign.keypair () in
  let sum12 = Sign.add pk1 pk2 in
  let sum23 = Sign.add pk2 pk3 in
  let a = Sign.add sum12 pk3 in
  let b = Sign.add pk1 sum23 in
  assert Cstruct.(Sign.(equal (to_cstruct a) (to_cstruct b)))

let arith () =
  let pk, sk = Sign.keypair () in
  let pk2 = Sign.mult pk (Z.of_int 3) in
  let pk2' = Sign.(add (add pk pk) pk) in
  Format.printf "\n%a\n%a\n"
    Hex.pp Hex.(of_cstruct (Sign.to_cstruct pk2))
    Hex.pp Hex.(of_cstruct (Sign.to_cstruct pk2')) ;
  assert Cstruct.(Sign.(equal (to_cstruct pk2) (to_cstruct pk2')))

let arith2 () =
  let a = Sign.base (Z.of_int 3) in
  let b = Sign.mult a (Z.of_int 2) in
  let b' = Sign.base (Z.of_int 6) in
  assert Cstruct.(Sign.(equal (to_cstruct b) (to_cstruct b')))

let basic = [
  "sha512", `Quick, sha512 ;
  "sign", `Quick, sign ;
  "sign_detached", `Quick, sign_detached ;
  "sign_extended", `Quick, sign_extended ;
  "sign_extended_detached", `Quick, sign_extended_detached ;
  "public", `Quick, public ;
  "base", `Quick, base ;
  "comm", `Quick, comm ;
  (* "assoc", `Quick, assoc ;
   * "arith", `Quick, arith ;
   * "arith2", `Quick, arith2 ; *)
]

let () =
  Alcotest.run "tweetnacl" [
    "basic", basic ;
  ]
