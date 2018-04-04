open Tweetnacl

let msg = "Voulez-vous coucher avec moi, ce soir ?" |> Cstruct.of_string
let msglen = Cstruct.len msg

let keypair () =
  let seed = Rand.gen 32 in
  let pk, sk = Sign.keypair ~seed () in
  let pk', sk' = Sign.keypair ~seed () in
  assert (Sign.equal pk pk') ;
  assert (Sign.equal sk sk')

let sign () =
  let pk, sk = Sign.keypair () in
  let signed_msg = Sign.sign ~key:sk msg in
  assert (Sign.verify ~key:pk signed_msg)

let sign_detached () =
  let pk, sk = Sign.keypair () in
  let signature = Sign.detached ~key:sk msg in
  assert (Sign.verify_detached ~key:pk ~signature msg)

let public () =
  let pk, sk = Sign.keypair () in
  let pk' = Sign.to_cstruct pk in
  let ppk = Sign.(public pk |> to_cstruct) in
  let psk = Sign.(public sk |> to_cstruct) in
  assert (Cstruct.equal pk' ppk) ;
  assert (Cstruct.equal pk' psk)

let secretbox () =
  let open Secretbox in
  let key = genkey () in
  let nonce = Nonce.gen () in
  let cmsg = box key nonce msg in
  assert (Cstruct.len cmsg = msglen + boxzerobytes) ;
  begin match box_open key nonce cmsg with
    | None -> assert false
    | Some msg' -> assert Cstruct.(equal msg msg')
  end

let secretbox_noalloc () =
  let open Secretbox in
  let buflen = msglen + zerobytes in
  let buf = Cstruct.create buflen in
  Cstruct.blit msg 0 buf zerobytes msglen ;
  let key = genkey () in
  let nonce = Nonce.gen () in
  box_noalloc key nonce buf ;
  let res = box_open_noalloc key nonce buf in
  assert res ;
  assert Cstruct.(equal msg (sub buf zerobytes msglen))

let secretbox = [
  "secretbox", `Quick, secretbox ;
  "secretbox_noalloc", `Quick, secretbox_noalloc ;
]

let box () =
  let open Box in
  let pk, sk = keypair () in
  let ck = combine pk sk in
  let nonce = Nonce.gen () in
  let cmsg = box pk sk nonce msg in
  assert (Cstruct.len cmsg = msglen + boxzerobytes) ;
  begin match box_open pk sk nonce cmsg with
    | None -> assert false
    | Some msg' -> assert Cstruct.(equal msg msg')
  end ;
  let cmsg = box_combined ck nonce msg in
  begin match box_open_combined ck nonce cmsg with
    | None -> assert false
    | Some msg' -> assert Cstruct.(equal msg msg')
  end

let box_noalloc () =
  let open Box in
  let buflen = msglen + zerobytes in
  let buf = Cstruct.create buflen in
  Cstruct.blit msg 0 buf zerobytes msglen ;
  let pk, sk = keypair () in
  let ck = combine pk sk in
  let nonce = Nonce.gen () in
  box_noalloc pk sk nonce buf ;
  let res = box_open_noalloc pk sk nonce buf in
  assert res ;
  assert Cstruct.(equal msg (sub buf zerobytes msglen)) ;
  box_combined_noalloc ck nonce buf ;
  let res = box_open_combined_noalloc ck nonce buf in
  assert res ;
  assert Cstruct.(equal msg (sub buf zerobytes msglen))

let box = [
  "box", `Quick, box ;
  "box_noalloc", `Quick, box_noalloc ;
]

let sign = [
  "keypair", `Quick, keypair ;
  "sign", `Quick, sign ;
  "sign_detached", `Quick, sign_detached ;
  "public", `Quick, public ;
]

let () =
  Alcotest.run "tweetnacl" [
    "secretbox", secretbox ;
    "box", box ;
    "sign", sign ;
  ]
