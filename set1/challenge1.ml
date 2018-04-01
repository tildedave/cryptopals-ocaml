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
end

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

  let pretty_char_to_hex c = Hashtbl.find char_to_hex_tbl c

  let int_to_hex_char i = hex_alphabet.[i]

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

    let from_hex_string str =
      let l = String.length str in
      let b = Bytes.create (l / 2) in
      let rec fill_bytes i =
        if i < l then
            (Bytes.set b (i / 2) (Char.chr ((pretty_char_to_hex str.[i] lsl 4) lxor (pretty_char_to_hex str.[i + 1])));
            fill_bytes (i + 2))
        else
            ()
      in
        assert (l mod 2 == 0);
        fill_bytes 0;
        b
end

open PrettyPrint;;

assert (pretty_char_to_hex 'f' == 15);;
assert (String.equal "4927" (to_hex_string (from_hex_string "4927")));;
