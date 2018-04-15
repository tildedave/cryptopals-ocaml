open Batteries
open Bits
open Crypto
open Encoding

(*

Break fixed-nonce CTR mode using substitutions
Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:

SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
say!")
Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is that I think this approach is suboptimal.

*)

let lines = [
  "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==";
  "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=";
  "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==";
  "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=";
  "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk";
  "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==";
  "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=";
  "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==";
  "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=";
  "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl";
  "VG8gcGxlYXNlIGEgY29tcGFuaW9u";
  "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==";
  "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=";
  "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==";
  "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=";
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";
  "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==";
  "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==";
  "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==";
  "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==";
  "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==";
  "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==";
  "U2hlIHJvZGUgdG8gaGFycmllcnM/";
  "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=";
  "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=";
  "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=";
  "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=";
  "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==";
  "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==";
  "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=";
  "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==";
  "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu";
  "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=";
  "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs";
  "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=";
  "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0";
  "SW4gdGhlIGNhc3VhbCBjb21lZHk7";
  "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=";
  "VHJhbnNmb3JtZWQgdXR0ZXJseTo=";
  "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";
]

let random_key = Bytes.to_string (Bits.random_bytes 16)

let fixed_nonce_ctr_cipher_stream key ciphertext =
  ctr_stream_cipher key 0 ciphertext

let encrypted_lines =
  List.map (fun bytes -> fixed_nonce_ctr_cipher_stream random_key bytes)
    (List.map from_base64_string lines)

let analyze_places () =
  let frequency_map = Hashtbl.create 10 in
  List.iter
    (fun line ->
      Bytes.iteri
        (fun n c ->
          let n_table = Hashtbl.find_default frequency_map n (Hashtbl.create 0) in
          let freq = Hashtbl.find_default n_table c 0 in
          begin
            Hashtbl.replace n_table c (freq + 1);
            Hashtbl.replace frequency_map n n_table
          end)
      line)
    encrypted_lines;
  List.iter (fun n ->
    let table = Hashtbl.find frequency_map n in
    Hashtbl.iter (fun k v ->
      Printf.printf "at position n=%d ---> %d occurred %d\n" n (Char.code k) v)
    (Hashtbl.filter (fun v -> v >= 6) table))
    (List.sort compare (List.of_enum (Hashtbl.keys frequency_map)))

let test_keystream_char c pos =
  List.fold_left
    (fun acc line ->
      if pos < Bytes.length line then
        (let d = Bytes.get line pos in
        let plaintext_char = lxor_char (Char.chr c) d in
        Set.add plaintext_char acc)
      else acc)
    Set.empty
    encrypted_lines

let test_decryption c pos lines =
  List.map
    (fun line ->
      Bytes.mapi (fun n s -> if n == pos then lxor_char c s else s) line)
  lines

let print_char_set c set =
  if Set.exists (fun d -> let code = Char.code d in code < 32 || code > 127) set then
    ()
  else
    Printf.printf "c=%d, set=>>> %s <<<\n" c (Set.fold (fun c acc -> String.of_char c ^
      (Printf.sprintf " (%d) " (Char.code c)) ^ acc) set "")

let run () =
  Printf.printf "*** CHALLENGE 19: Break fixed-nonce CTR mode using substitutions ***\n";
  (* let's find the e characters *)
  (* e = key (unknown) ^ cipher *)
  (* if we have places with e > 3 that is probably a hit on the keystream? *)
  analyze_places ();
  (*
    position n=2 ---> 112 occurred 11
    position n=3 ---> 224 occurred 10
    position n=6 ---> 206 occurred 10
    position n=10 ---> 41 occurred 11
    position n=12 ---> 180 occurred 10
    position n=20 ---> 181 occurred 10

    Plaintext 'e' at position 2.  Ciphertext 112 means that the keystream at this digit would be
    112 lxor 21 (= Char.code e) = 101.  Let's see what assuming 101 keystream at #2 does to the
    rest of the text.  It should 'unfuck' the text and mostly should result in ASCII thingies.
  *)

  (* position 2 = 32 also ??? :| *)
  (* position 3 =  :| *)
  (* position 12 = 32 *)
  (* List.iter
    (fun c -> print_char_set c (test_keystream_char (179 lxor c) 1))
    (Util.range 0 255); *)
  let char_for_line_at_pos line_no pos = Bytes.get (List.nth encrypted_lines line_no) pos in
  Printf.printf "char for 0 --> %d\n" (Char.code (lxor_char (char_for_line_at_pos 20 0) 'W'));
  Printf.printf "---\n";
  (*
    position 1 = 179 lxor 101
    position 2 = 32 lxor 224
    position 3 = 32 lxor 112

    position 0 = 84 lxor 78  = 65 lxor 91 = 26
      also possible 78 lxor 116  84
  *)

  if true then
    List.iteri
      (fun n line -> Printf.printf "n=%d %s\n" n (Bytes.to_string line))
      (List.fold_lefti
        (fun acc pos c -> test_decryption c pos acc)
        encrypted_lines
        [Char.chr 26;
         Char.chr (179 lxor 101);
         Char.chr (32 lxor 112);
         Char.chr (32 lxor 224);
         lxor_char (char_for_line_at_pos 3 4) 't';
         lxor_char (char_for_line_at_pos 1 5) 'g';
         lxor_char (char_for_line_at_pos 3 6) 'e';
         lxor_char (char_for_line_at_pos 3 7) 'n';
         lxor_char (char_for_line_at_pos 5 8) 'e';
         lxor_char (char_for_line_at_pos 11 9) 'e';
         lxor_char (char_for_line_at_pos 0 10) ' ';
         lxor_char (char_for_line_at_pos 1 11) ' ';
         lxor_char (char_for_line_at_pos 0 12) 'h';
         lxor_char (char_for_line_at_pos 0 13) 'e';
         lxor_char (char_for_line_at_pos 0 14) ' ';
       ])
  else
    ()

