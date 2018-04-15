open Batteries
open Encoding
open Padding
open Util

(*
ECB cut-and-paste
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
*)

let profile_from_cookie cookie_str =
  let map = Hashtbl.create 10 in
  List.iter
    (fun (k, v) -> Hashtbl.replace map k v)
    (List.map (fun item -> String.split item "=") (String.nsplit cookie_str "&"));
  map

let profile_for email =
  let safe_email = String.replace_chars
    (fun c -> if c == '&' || c == '=' then "" else String.of_char c) email in
  List.fold_left
    (fun acc (k, v) -> (if String.length acc == 0 then "" else acc ^ "&") ^ k ^ "=" ^ v)
    ""
    [("email", safe_email);("uid", String.of_int 10);("role", "user")]

let random_key = Bytes.to_string (Bits.random_bytes 16)

let encrypted_profile_for email =
  Crypto.aes_ecb_encrypt
    (pad_to_blocksize pad_pkcs7 (Bytes.of_string (profile_for email)) 16)
    random_key

let decrypt_profile_for ciphertext =
  let decrypted = Crypto.aes_ecb_decrypt ciphertext random_key in
  profile_from_cookie (Bytes.to_string decrypted)

let run () =
  Printf.printf "*** CHALLENGE 13: ECB cut-and-paste ***\n";
  let p = profile_from_cookie "foo=bar&baz=qux&zap=zazzle" in
  List.iter
    (fun (k,v) -> assert (String.equal (Hashtbl.find p k) v))
    [("foo","bar");("baz","qux");("zap","zazzle")];
  let q = profile_for "lucky@example.com" in
  let ciphertext = encrypted_profile_for "lucky@example.com" in
  assert (String.starts_with (Hashtbl.find (decrypt_profile_for ciphertext) "role") "user");
  let blocksize = 16 in
  (* get an admin\PAD\PAD\PAD block *)
  let prefix = String.make (blocksize - (String.length "email=")) 'a' in
  let padding_bytes = blocksize - String.length "admin" in
  let admin_block = "admin" ^ String.make padding_bytes (Char.chr padding_bytes) in
  let attacker_ciphertext = encrypted_profile_for (prefix ^ admin_block) in
  let paste = Bits.nth_block attacker_ciphertext 1 blocksize in
  (* email=&uid=10&role= has length 19 so we just need to make a fake email of size
     32 - 19, grab the first two bytes, then paste in the admin role *)
  let attacker_ciphertext = encrypted_profile_for "3@example.com" in
  let block1, block2 = mapt2 (fun i -> Bits.nth_block attacker_ciphertext i blocksize) (0, 1) in
  let modified_ciphertext = Bytes.concat (Bytes.create 0) [block1; block2; paste] in
  (* decrypt function should strip padding off at the end so this can be strict equality *)
  assert (String.starts_with (Hashtbl.find (decrypt_profile_for modified_ciphertext) "role") "admin");
  Printf.printf "🎉 All assertions complete! 🎉\n"
