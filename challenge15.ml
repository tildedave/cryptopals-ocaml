open Bits
open Encoding

(*
PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
*)

exception Bad_Padding

let strip_pkcs7_padding plaintext blocksize =
  let block = last_block plaintext blocksize in
  let c = Char.code (Bytes.get plaintext (blocksize - 1)) in
  if c > 16 then
    (* no strip *)
    plaintext
  else
    let padding_area = Bytes.sub plaintext (blocksize - c) c in
    Bytes.iter (fun b -> if (Char.code b) <> c then raise Bad_Padding else ()) padding_area;
    Bytes.sub plaintext 0 (blocksize - c)

let run () =
  Printf.printf "*** CHALLENGE 15: PKCS#7 padding validation ***\n";
  let test_plaintext plaintext expected =
    assert (String.equal
      (Bytes.to_string (strip_pkcs7_padding (Bytes.of_string plaintext) 16))
      expected) in
  let test_plaintext_failure plaintext =
    let failed = ref false in
    begin
      try strip_pkcs7_padding (Bytes.of_string plaintext) 16; ()
      with Bad_Padding -> failed := true
    end;
    assert !failed in
  test_plaintext "ICE ICE BABY\x04\x04\x04\x04" "ICE ICE BABY";
  test_plaintext_failure "ICE ICE BABY\x05\x05\x05\x05";
  test_plaintext_failure "ICE ICE BABY\x01\x02\x03\x04";
  test_plaintext "YELLOW SUBMARINE" "YELLOW SUBMARINE";
  Printf.printf "🎉 All assertions complete! 🎉\n"
