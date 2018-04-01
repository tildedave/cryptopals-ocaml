#use "util.ml"

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

assert (String.equal "4927" (to_hex_string (from_hex_string "4927")));;
assert (String.equal "SSdt" (to_base64_string (from_base64_string "SSdt")));;
