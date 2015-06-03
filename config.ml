open Mirage

let main =
  foreign "Unikernel.Main" (console @-> kv_ro @->  job)

let disk1 = crunch "pcaps"

let () =
  add_to_opam_packages["pcap-format"; "tcpip"; "mirage-net-pcap"; "mirage-clock-unix"];
  add_to_ocamlfind_libraries["pcap-format"; "tcpip.ethif"; "tcpip.ipv4"; "tcpip.tcp";
                             "mirage-net-pcap"; "cstruct.syntax"; "mirage-clock-unix"];
  register "trace-checker" [ main $ default_console $ disk1 ]