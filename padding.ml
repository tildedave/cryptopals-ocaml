open Bits

let pad_pkcs7 bytes blocklen =
  let l = Bytes.length bytes in
  assert (blocklen > l);
  let padding_len = blocklen - l in
  let b = (Bytes.extend bytes 0 padding_len) in
  Bytes.fill b l padding_len (Char.chr padding_len);
  b

let pad_to_blocksize pad_func bytes blocksize =
  let len = Bytes.length bytes in
  if len mod blocksize == 0
  then
    bytes
  else
    pad_func bytes (len + (blocksize - len mod blocksize))

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
