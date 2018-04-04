open Batteries

(* Utility functions *)

let mapt2 f (a, b) = (f a, f b)
let mapt3 f (a, b, c) = (f a, f b, f c)
let mapt4 f (a, b, c, d) = (f a, f b, f c, f d)

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

let split_bytes bytes size =
  let buckets = Hashtbl.create size in
    List.iter (fun k -> Hashtbl.add buckets k Bytes.empty) (range 0 size);
    Bytes.iteri (fun n c ->
      let k = n mod size in
      let bucket = Hashtbl.find buckets k in
      (* this is stupid inefficient *)
      Hashtbl.replace buckets k (Bytes.cat bucket (Bytes.make 1 c))
    ) bytes;
    List.fold_left (fun acc n -> Hashtbl.find buckets n :: acc) [] (List.rev (range 0 size))
