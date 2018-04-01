(*

Convert hex to base64

The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

*)

(* byte = 8 bits *)

module type PrettyPrint_type = sig
  val to_hex_string : bytes -> string
  val from_hex_string : string -> bytes
  val from_base64_string : string -> bytes
  val to_base64_string : bytes -> string
  val base64_char_to_int : char -> int
  val hex_char_to_int : char -> int
end

let mapt2 f (a, b) = (f a, f b);;
let mapt3 f (a, b, c) = (f a, f b, f c);;
let mapt4 f (a, b, c, d) = (f a, f b, f c, f d);;

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

let assert_with_message b msg =
  if not b then
    failwith msg
  else
    ()

module PrettyPrint : PrettyPrint_type = struct
  let hex_alphabet = "0123456789abcdef"
  let base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  let char_to_hex_tbl = Hashtbl.create (String.length hex_alphabet)
  let char_to_base64_tbl = Hashtbl.create (String.length base64_alphabet)

  let _ =
    for i = 0 to String.length hex_alphabet - 1 do
      Hashtbl.add char_to_hex_tbl hex_alphabet.[i] i
    done;
    for i = 0 to String.length base64_alphabet - 1 do
      Hashtbl.add char_to_base64_tbl base64_alphabet.[i] i
    done

  let hex_char_to_int c = Hashtbl.find char_to_hex_tbl c
  let int_to_hex_char i = hex_alphabet.[i]

  let base64_char_to_int c = Hashtbl.find char_to_base64_tbl c
  let int_to_base64_char i = base64_alphabet.[i]

  let to_hex_string bytes =
    let l = Bytes.length bytes in
    let s = Bytes.create (l * 2) in
    let rec fill_string i =
      if i < l * 2 then
        let b = Char.code (Bytes.get bytes (i / 2)) in
        Bytes.set s i (int_to_hex_char ((b land 0xF0) lsr 4));
        Bytes.set s (i + 1) (int_to_hex_char (b land 0x0F));
        fill_string (i + 2)
      else
        ()
    in
      assert (l mod 2 == 0);
      fill_string 0;
      Bytes.to_string s

    let to_base64_string bytes =
      let l = Bytes.length bytes in
      (* l * 8 = # bits *)
      let s = Bytes.create ((l / 3) * 4) in
      let rec fill_string i j =
        if j < l - 1 then
          (* unpack 4 characters 3 at a time *)
          (let (c1, c2, c3) = mapt3 (Bytes.get bytes) (j, j + 1, j + 2) in
          let (b1, b2, b3, b4) = mapt4 int_to_base64_char (unpack6 c1 c2 c3) in
          Bytes.set s i b1;
          Bytes.set s (i + 1) b2;
          Bytes.set s (i + 2) b3;
          Bytes.set s (i + 3) b4;
          fill_string (i + 4) (j + 3))
        else
          ()
      in
        assert (l mod 3 == 0);
        fill_string 0 0;
        Bytes.to_string s

    let from_hex_string str =
      let l = String.length str in
      let b = Bytes.create (l / 2) in
      let rec fill_bytes i =
        if i < l then
          let (b1, b2) = mapt2 hex_char_to_int (str.[i], str.[i + 1]) in
          (Bytes.set b (i / 2) (pack4 b1 b2);
          fill_bytes (i + 2))
        else
            ()
      in
        assert (l mod 2 == 0);
        fill_bytes 0;
        b

    let from_base64_string str =
      let l = String.length str in
      (* 1 char becomes 6 bits = 1.5 bytes *)
      let b = Bytes.create (l * 3 / 4) in
      let rec fill_bytes i j =
        if i < l then
          (let (n1, n2, n3, n4) = mapt4 base64_char_to_int (str.[i], str.[i + 1], str.[i + 2], str.[i + 3]) in
           let (c1, c2, c3) = pack6 n1 n2 n3 n4 in
            Bytes.set b j c1;
            Bytes.set b (j + 1) c2;
            Bytes.set b (j + 2) c3;
            fill_bytes (i + 4) (j + 3))
        else
          ()
      in
        assert (l mod 4 == 0);
        fill_bytes 0 0;
        b
end

open PrettyPrint;;

assert (pretty_char_to_hex 'f' == 15);;
assert (String.equal "4927" (to_hex_string (from_hex_string "4927")));;
assert (String.equal "SSdt" (to_base64_string (from_base64_string "SSdt")));;

let challenge1_hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";;
let challenge1_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";;

assert (String.equal (to_base64_string (from_hex_string challenge1_hex_string)) challenge1_base64_string);;
assert (String.equal (to_hex_string (from_base64_string challenge1_base64_string)) challenge1_hex_string);;
