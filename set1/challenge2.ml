(*

Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179

*)

#use "prettyprint.ml"

open PrettyPrint;;

let fixed_xor bytes1 bytes2 =
    assert (Bytes.length bytes1 == Bytes.length bytes2);
    Bytes.mapi (fun n b1 ->
        let b2 = Bytes.get bytes2 n in
        Char.chr ((Char.code b1) lxor (Char.code b2)))
        bytes1

let s1 = from_hex_string "1c0111001f010100061a024b53535009181c";;
let s2 = from_hex_string "686974207468652062756c6c277320657965";;

assert (String.equal (to_hex_string (fixed_xor s1 s2)) "746865206b696420646f6e277420706c6179");;
