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
  pad_func bytes (len + (blocksize - len mod blocksize))

exception Bad_Padding

let strip_pkcs7_padding plaintext blocksize =
  let blocks = num_blocks plaintext blocksize in
  let block = nth_block plaintext (blocks - 1) blocksize in
  let c = Char.code (Bytes.get block (blocksize - 1)) in
  if c > blocksize || c == 0 then
    raise Bad_Padding
  else
    let padding_area = Bytes.sub block (blocksize - c) c in
    Bytes.iter (fun b -> if (Char.code b) <> c then raise Bad_Padding else ()) padding_area;
    Bytes.cat
      (Bytes.sub (Bytes.copy plaintext) 0 ((blocks - 1) * blocksize))
      (Bytes.sub block 0 (blocksize - c))
