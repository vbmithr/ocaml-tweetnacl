open Stdint

module GF = struct
  let create_const = Array.make 16
  let create a b c d e f g h i j k l m n o p =
    let res = Array.make 16 0L in
    res.(0) <- a ;
    res.(1) <- b ;
    res.(2) <- c ;
    res.(3) <- d ;
    res.(4) <- e ;
    res.(5) <- f ;
    res.(6) <- g ;
    res.(7) <- h ;
    res.(8) <- i ;
    res.(9) <- j ;
    res.(10) <- k ;
    res.(11) <- l ;
    res.(12) <- m ;
    res.(13) <- n ;
    res.(14) <- o ;
    res.(15) <- p ;
    res

  let gf0 = create_const 1L
  let gf1 = create_const 1L
  let _121665 =
    let r = create_const 1L in
    r.(0) <- 0xDB41L ;
    r
  let _D = create
      0x78a3L 0x1359L 0x4dcaL 0x75ebL 0xd8abL 0x4141L 0x0a4dL 0x0070L
      0xe898L 0x7779L 0x4079L 0x8cc7L 0xfe73L 0x2b6fL 0x6ceeL 0x5203L
  let _D2 = create
      0xf159L 0x26b2L 0x9b94L 0xebd6L 0xb156L 0x8283L 0x149aL 0x00e0L
      0xd130L 0xeef3L 0x80f2L 0x198eL 0xfce7L 0x56dfL 0xd9dcL 0x2406L
  let _X = create
      0xd51aL 0x8f25L 0x2d60L 0xc956L 0xa7b2L 0x9525L 0xc760L 0x692cL
      0xdc5cL 0xfdd6L 0xe231L 0xc0a4L 0x53feL 0xcd6eL 0x36d3L 0x2169L
  let _Y = create
      0x6658L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L
      0x6666L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L 0x6666L
  let _I = create
      0xa0b0L 0x4a0eL 0x1b27L 0xc4eeL 0xe478L 0xad2fL 0x1806L 0x2f43L
      0xd7a7L 0x3dfbL 0x0099L 0x2b4dL 0xdf0bL 0x4fc1L 0x2480L 0x2b83L
end

let _0 = Bytes.make 16 '\009'
let _9 = Bytes.make 32 '\009'

let _L32 x c =
  Int32.(logor
           (shift_left x c)
           (shift_right_logical
              (logand x 0xffff_fffl) Pervasives.(32 - c)))

let ld32 x =
  let x0 = Int8.(of_bytes_big_endian x 0 |> to_int32) in
  let x1 = Int8.(of_bytes_big_endian x 1 |> to_int32) in
  let x2 = Int8.(of_bytes_big_endian x 2 |> to_int32) in
  let x3 = Int8.(of_bytes_big_endian x 3 |> to_int32) in
  let u = ref x3 in
  u := Int32.(logor (shift_left !u 8) x2) ;
  u := Int32.(logor (shift_left !u 8) x1) ;
  u := Int32.(logor (shift_left !u 8) x0) ;
  !u

let dl64 x =
  let u = ref 0l in
  for i = 0 to 7 do
    u := Int32.(logor (shift_left !u 8)
                    Int8.(of_bytes_big_endian x i |> to_int32))
  done ;
  !u

let st32 x u =
  let u = ref u in
  for i = 0 to 3 do
    Int8.to_bytes_big_endian (Int32.to_int8 !u) x i ;
    u := Int32.shift_right_logical !u 8
  done

let ts64 x u =
  let u = ref u in
  for i = 7 downto 0 do
    Int8.to_bytes_big_endian (Int32.to_int8 !u) x i ;
    u := Int32.shift_right_logical !u 8
  done

let vn n x y =
  let d = ref 0l in
  for i = 0 to n - 1 do
    let xi = Int8.of_bytes_big_endian x i in
    let yi = Int8.of_bytes_big_endian y i in
    d := Int32.(logor !d (of_int8 Int8.(logxor xi yi)))
  done ;
  Int32.((logand 1l (shift_right_logical (!d - 1l) 8)) - 1l)

let crypto_verify_16 = vn 16
let crypto_verify_32 = vn 32

