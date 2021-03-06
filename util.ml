open Batteries

(* Utility functions *)

let mapt2 f (a, b) = (f a, f b)
let mapt3 f (a, b, c) = (f a, f b, f c)
let mapt4 f (a, b, c, d) = (f a, f b, f c, f d)

let rec gcd n m = let r = n mod m in if r == 0 then m else gcd m r
let imod m n = let a = m mod n in if a < 0 then a + n else a

let _ =
  assert ((gcd 6 2) == 2);
  assert ((gcd 6 4) == 2);
  assert ((gcd 15 13) == 1)

let hashtbl_items h = Hashtbl.fold (fun k v l -> (k, v) :: l)  h []
let hashtbl_find_with_default h k d =
  match Hashtbl.find_option h k with
  | None -> d
  | Some v -> v

let range m n =
  let rec range_helper i j =
    if i == j then [] else i :: range_helper (i + 1) j
  in
    assert (m >= 0);
    assert (n >= 0);
    assert (m < n);
    range_helper m n

(* Not efficient ;) *)
let implode cl = String.concat "" (List.map (String.make 1) cl);;

let rec take l n =
  if n = 0 then
    []
  else
    match l with
    | [] -> []
    | x :: xs -> x :: (take xs (n - 1));;

let rec replace_all str sub by =
  let b, s = String.replace str sub by in if b then replace_all s sub by else s

let assert_strings_equal str expected = assert (String.equal str expected)

let assert_bytes_equal bytes expected = assert (Bytes.equal bytes expected)

let bytes_to_hex_string bytes =
  let s = ref "" in
  for i = 0 to Bytes.length bytes - 1 do
    s := (!s) ^ (Printf.sprintf "%x" (Char.code (Bytes.get bytes i)))
  done;
  !s
