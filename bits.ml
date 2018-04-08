open Util
open Batteries

(* pack 2 4 bit integers into 1 char *)
let pack4 m n =
  assert (m land 0x0F == m);
  assert (n land 0x0F == n);
  Char.chr ((m lsl 4) lxor n)

(* pack 4 6 bit integers into 3 chars *)
let pack6 m n o p =
  assert (m land 0x3F == m);
  assert (n land 0x3F == n);
  assert (o land 0x3F == o);
  assert (p land 0x3F == p);
  mapt3 Char.chr
    ((m lsl 2) lxor (n lsr 4),
    ((n land 0xF) lsl 4) lxor (o lsr 2),
    ((o land 0x3) lsl 6) lxor p)

let unpack4 c = let b = Char.code c in ((b land 0xF0) lsr 4, b land 0x0F)

let unpack6 m n o =
  let b1, b2, b3 = mapt3 Char.code (m, n, o) in
  (
    (* 6 MSB of b1 *)
    b1 lsr 2,
    (* 2 LSB of b1, 4 MSB of b2 *)
    ((b1 land 0x3) lsl 4) lxor (b2 lsr 4),
    (* 4 LSB of b1, 2 MSB of b2 *)
    ((b2 land 0xF) lsl 2) lxor (b3 lsr 6),
    (* 6 LSB of b3 *)
    b3 land 0x3F)

let char_apply f c1 c2 = Char.chr (f (Char.code c1) (Char.code c2))
let lxor_char c1 c2 = char_apply (lxor) c1 c2

let bytes_apply f bytes1 bytes2 =
  assert (Bytes.length bytes1 == Bytes.length bytes2);
  Bytes.mapi (fun n b -> f b (Bytes.get bytes2 n)) bytes1

let fixed_xor bytes1 bytes2 = bytes_apply lxor_char bytes1 bytes2

let repeating_key_xor bytes key =
  let k_length = String.length key in
  Bytes.mapi (fun n b -> lxor_char b key.[n mod k_length]) bytes

let num_set_bits n =
  let rec num_set_bits_helper m i =
    if m == 0 then
      i
    else
      num_set_bits_helper (m lsr 1) (i + if m mod 2 == 1 then 1 else 0)
  in
    num_set_bits_helper n 0

let hamming_distance bytes1 bytes2 =
  assert (Bytes.length bytes1 == Bytes.length bytes2);
  let d = ref 0 in
  Bytes.iteri (fun n c1 ->
    let (b1, b2) = mapt2 Char.code (c1, Bytes.get bytes2 n) in
    let dist = b1 lxor b2 in
    d := !d + (num_set_bits dist)) bytes1;
  !d

let random_bytes keysize =
  (Bytes.of_string (String.of_enum (Enum.take keysize (Random.enum_char ()))))

let num_repetitions bytes block_size =
  let hash_blocks = Hashtbl.create 20 in
  let repeated = ref 0 in
  for i = 0 to (Bytes.length bytes) - 1 - block_size do
    let s = Bytes.sub bytes i block_size in
    let v = (Hashtbl.find_default hash_blocks s 0) in
    Hashtbl.replace hash_blocks s (v + 1);
    if v > 0 then
      repeated := !repeated + 1
    else
      ()
  done;
  !repeated

let nth_block bytes i blocksize = Bytes.sub bytes (i * blocksize) blocksize

let first_block bytes = nth_block bytes 0

let _ =
  assert (num_set_bits 3 == 2);
  assert (num_set_bits 7 == 3);
  assert (num_set_bits 8 == 1);
  assert (num_set_bits 0 == 0);
  assert (num_set_bits 15 == 4);
  let (s1, s2) = (Bytes.of_string "this is a test", Bytes.of_string "wokka wokka!!!") in
    assert ((hamming_distance s1 s2) == 37)
