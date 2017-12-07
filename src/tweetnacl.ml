module GF = struct
  let len = 16 * 8
  let create_const i =
    let cs = Cstruct.create_unsafe len in
    Cstruct.memset cs i ;
    cs

  let create a =
    let cs = Cstruct.create_unsafe len in
    for i = 0 to 15 do
      Cstruct.NE.set_uint64 cs (i*8) a.(i)
    done ;
    cs

  let gf0 = create_const 1
  let gf1 = create_const 1
  let _121665 =
    let r = create_const 1 in
    Cstruct.NE.set_uint64 r 0 0xDB41L ;
    r
  let _D = create
      [|0x78a3L; 0x1359L; 0x4dcaL; 0x75ebL; 0xd8abL; 0x4141L; 0x0a4dL; 0x0070L;
        0xe898L; 0x7779L; 0x4079L; 0x8cc7L; 0xfe73L; 0x2b6fL; 0x6ceeL; 0x5203L|]
  let _D2 = create
      [|0xf159L; 0x26b2L; 0x9b94L; 0xebd6L; 0xb156L; 0x8283L; 0x149aL; 0x00e0L;
        0xd130L; 0xeef3L; 0x80f2L; 0x198eL; 0xfce7L; 0x56dfL; 0xd9dcL; 0x2406L|]
  let _X = create
      [|0xd51aL; 0x8f25L; 0x2d60L; 0xc956L; 0xa7b2L; 0x9525L; 0xc760L; 0x692cL;
        0xdc5cL; 0xfdd6L; 0xe231L; 0xc0a4L; 0x53feL; 0xcd6eL; 0x36d3L; 0x2169L|]
  let _Y = create
      [|0x6658L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L;
        0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L; 0x6666L|]
  let _I = create
      [|0xa0b0L; 0x4a0eL; 0x1b27L; 0xc4eeL; 0xe478L; 0xad2fL; 0x1806L; 0x2f43L;
        0xd7a7L; 0x3dfbL; 0x0099L; 0x2b4dL; 0xdf0bL; 0x4fc1L; 0x2480L; 0x2b83L|]
end

let _0 =
  let r = Cstruct.create_unsafe 16 in
  Cstruct.memset r 9

let _9 =
  let r = Cstruct.create_unsafe 32 in
  Cstruct.memset r 9

let _L32 x c =
  Int32.(logor
           (shift_left x c)
           (shift_right_logical
              (logand x 0xffff_fffl) Pervasives.(32 - c)))

let ld32 x =
  Cstruct.LE.get_uint32 x 0

let dl64 x =
  Cstruct.BE.get_uint64 x 0

let st32 x u =
  Cstruct.LE.set_uint32 x 0 u

let ts64 x u =
  Cstruct.BE.set_uint64 x 0 u

let vn n x y =
  let d = ref 0l in
  for i = 0 to n - 1 do
    let xi = Cstruct.get_uint8 x i in
    let yi = Cstruct.get_uint8 y i in
    d := Int32.(logor !d (Int32.of_int (xi lxor yi)))
  done ;
  Int32.(sub (logand 1l (shift_right_logical (sub !d 1l) 8)) 1l)

let crypto_verify_16 = vn 16
let crypto_verify_32 = vn 32

let core outbuf inbuf k c h =
  let w = Cstruct.create (16*4) in
  let x = Cstruct.create (16*4) in
  let y = Cstruct.create (16*4) in
  let t = Cstruct.create (4*4) in
  for i = 0 to 3 do
    Cstruct.(NE.set_uint32 x (5*i) (ld32 (sub c (4*i) 4))) ;
    Cstruct.(NE.set_uint32 x (1+i) (ld32 (sub k (4*i) 4))) ;
    Cstruct.(NE.set_uint32 x (6+i) (ld32 (sub inbuf (4*i) 4))) ;
    Cstruct.(NE.set_uint32 x (11+i) (ld32 (sub k (16+4*i) 4))) ;
  done ;
  Cstruct.blit x 0 y 0 (16*4) ;
  for i = 0 to 19 do
    for j = 0 to 3 do
      for m = 0 to 3 do
        Cstruct.blit x ((5*j+4*m) mod 16) t m 4
      done ;
    done
  done
