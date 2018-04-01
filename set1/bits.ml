open Util

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

let lxor_char c1 c2 = Char.chr ((Char.code c1) lxor (Char.code c2))

let fixed_xor bytes1 bytes2 =
    assert (Bytes.length bytes1 == Bytes.length bytes2);
    Bytes.mapi (fun n b1 -> lxor_char b1 (Bytes.get bytes2 n)) bytes1

let repeating_key_xor bytes key =
  let k_length = String.length key in
  let r = ref 0 in
  Bytes.mapi (fun n b -> lxor_char b key.[n mod k_length]) bytes
