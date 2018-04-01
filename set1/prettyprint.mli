module type PrettyPrint_type = sig
  val to_hex_string : bytes -> string
  val from_hex_string : string -> bytes
  val from_base64_string : string -> bytes
  val to_base64_string : bytes -> string
  val base64_char_to_int : char -> int
  val hex_char_to_int : char -> int
end
