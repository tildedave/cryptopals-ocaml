open Bits
open Encoding
open Padding

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
  Printf.printf "🎉 All assertions complete! 🎉\n"
