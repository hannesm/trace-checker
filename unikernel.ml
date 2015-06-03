open V1_LWT
open Lwt

module Main (C: CONSOLE) (K: KV_RO) = struct
  module P = Netif.Make(K)(OS.Time)
  module E = Ethif.Make(P)
  module I = Ipv4.Make(E)(Clock)(OS.Time)
  module T = Tcp.Flow.Make(I)(OS.Time)(Clock)(Random)
  (*  module Stack = Tcpip_stack_direct.Make(C)(OS.Time)(Random)(Netif)(Stackv41_E)(Stackv41_I)(Stackv41_U)(Stackv41_T) *)

  let file = "dump-ff.pcap"

  (* guess that is ok... *)
  let ip = Ipaddr.V4.of_string_exn "1.1.1.1"
  let nm = Ipaddr.V4.of_string_exn "0.0.0.0"

  let printer = function
    | `Success -> "Success"
    | `Failure s -> s

  let start c k =

    let or_error c name fn t =
      fn t >>= function
      | `Error e -> fail (Failure ("Error starting " ^ name))
      | `Ok t -> return t
    in

    let not_initialised = ref true in
    let client t tcp dest_ip =
      let src_port = Wire_structs.Tcp_wire.get_tcp_src_port tcp
      and dest_port = Wire_structs.Tcp_wire.get_tcp_dst_port tcp
      and isn = Tcp.Sequence.of_int (Int32.to_int (Wire_structs.Tcp_wire.get_tcp_sequence tcp))
      and window = Wire_structs.Tcp_wire.get_tcp_window tcp
      in
      T.connect_pcb ~window ~isn ~src_port t ~dest_ip ~dest_port
    in

    let server_cb flow =
      Printf.printf "server callback\n%!" ;
      (*      Lwt.return_unit*)
      T.read flow >>= function
      | `Ok buf -> Printf.printf "received" ; Cstruct.hexdump buf ; Lwt.return_unit
        | err -> Lwt.return_unit
    in
    let i = ref 0 in
    let recv_ip t buf =
      let proto = Wire_structs.Ipv4_wire.get_ipv4_proto buf in
      match Wire_structs.Ipv4_wire.int_to_protocol proto with
      | Some `TCP ->
        let dst = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_dst buf)
        and src = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_src buf)
        and ihl = (Wire_structs.Ipv4_wire.get_ipv4_hlen_version buf land 0xf) * 4 in
        let _, tcp = Cstruct.split buf ihl
        in
        if !not_initialised then
          begin
            (* we assume to have a SYN here! *)
            let src_port = Wire_structs.Tcp_wire.get_tcp_src_port tcp in
            let dst_port = Wire_structs.Tcp_wire.get_tcp_dst_port tcp in
            (*client t tcp dst >>= fun client_flow -> *)
            
            not_initialised := false
          end ;
        Printf.printf "received tcp %d (%s -> %s):" !i (Ipaddr.V4.to_string src) (Ipaddr.V4.to_string dst); Cstruct.hexdump tcp ;
        i := succ !i ;
        Lwt.async (fun () -> T.input t ~listeners:(function 443 -> Some server_cb | _ -> None) ~src ~dst tcp);
        Lwt.return_unit
      | _ -> Lwt.return_unit
    in
    let setup_iface ?(timing=None) file ip nm =

      let pcap_netif_id = P.id_of_desc ~mac:Macaddr.broadcast ~timing ~source:k ~read:file in
      (* build interface on top of netif *)
      or_error c "pcap_netif" P.connect pcap_netif_id >>= fun p ->
      or_error c "ethif" E.connect p >>= fun e ->
      E.enable_promiscuous_mode e ;
      or_error c "ipv4" I.connect e >>= fun i ->
      or_error c "tcpv4" T.connect i >>= fun t ->

      (* set up ipv4 statically *)
      I.set_ip i ip >>= fun () -> I.set_ip_netmask i nm >>= fun () ->

      Lwt.return (p, e, i, t)
    in
    let play_pcap (p, e, i, t) =
      P.listen p (E.input
                    ~arpv4:(fun buf -> Lwt.return_unit)
                    ~ipv4:(fun buf -> recv_ip t buf)
                    ~ipv6:(fun buf -> Lwt.return_unit) e
                 ) >>= fun () ->
      Lwt.return (p, e, i, t)
    in
    Lwt.async_exception_hook := (fun e ->
        Printf.printf "exception %s, backtrace\n%s"
          (Printexc.to_string e) (Printexc.get_backtrace ())) ;
    setup_iface file ip nm >>= fun send_arp_test_stack ->
    play_pcap send_arp_test_stack >>= fun (p, e, i, t) ->
    (* test_send_arps p e u >>= fun result ->
       assert_equal ~printer `Success result; *)
    Lwt.return_unit
end
