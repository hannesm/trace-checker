open V1_LWT
open Lwt

module Main (C: CONSOLE) (K: KV_RO) = struct
  module P = Netif.Make(K)(OS.Time)
  module E = Ethif.Make(P)
  module I = Ipv4.Make(E)(Clock)(OS.Time)
  module T = Tcp.Flow.Make(I)(OS.Time)(Clock)(Random)
  (*  module Stack = Tcpip_stack_direct.Make(C)(OS.Time)(Random)(Netif)(Stackv41_E)(Stackv41_I)(Stackv41_U)(Stackv41_T) *)

  let file = "tlssession.pcap"

  (* guess that is ok... *)
  let ip = Ipaddr.V4.of_string_exn "1.1.1.1"
  let nm = Ipaddr.V4.of_string_exn "0.0.0.0"

  let start c k =

    let or_error c name fn t =
      fn t >>= function
      | `Error e -> fail (Failure ("Error starting " ^ name))
      | `Ok t -> return t
    in

    let not_initialised = ref true in
    let client t tcp src dest_ip =
      let src_port = Wire_structs.Tcp_wire.get_tcp_src_port tcp
      and dest_port = Wire_structs.Tcp_wire.get_tcp_dst_port tcp
      and isn = Tcp.Sequence.of_int (Int32.to_int (Wire_structs.Tcp_wire.get_tcp_sequence tcp))
      and window = Wire_structs.Tcp_wire.get_tcp_window tcp
      in
      Printf.printf "setting up TCB for client: %s %d %s %d\n"
        (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dest_ip) dest_port ;
      T.connect_pcb ~window ~isn ~src_port t ~dest_ip ~dest_port
    in

    let server_data = ref [] in
    let client_data = ref [] in

    let server_cb flow =
      Printf.printf "server callback\n%!" ;
      let rec recv () =
        T.read flow >>= function
        | `Ok buf -> server_data := buf :: !server_data ; recv ()
        | err -> Lwt.return_unit
      in
      recv ()
    in
    let client_cb flow =
      Printf.printf "client callback\n%!" ;
      let rec recv () =
        T.read flow >>= function
        | `Ok buf -> client_data := buf :: !client_data ; recv ()
        | err -> Lwt.return_unit
      in
      recv ()
    in

    let i = ref 1 in
    let first : Cstruct.t option ref = ref None in
    let recv_ip ip t buf =
      let proto = Wire_structs.Ipv4_wire.get_ipv4_proto buf in
      match Wire_structs.Ipv4_wire.int_to_protocol proto with
      | Some `TCP ->
        let dst = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_dst buf)
        and src = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_src buf)
        and ihl = (Wire_structs.Ipv4_wire.get_ipv4_hlen_version buf land 0xf) * 4 in
        let _, tcp = Cstruct.split buf ihl
        in
        let src_port = Wire_structs.Tcp_wire.get_tcp_src_port tcp in
        let dst_port = Wire_structs.Tcp_wire.get_tcp_dst_port tcp in
        (match !first with
         | Some x ->
           (* tcp better be a synack *)
           (* for the server side, we prepare a special sequence number :) *)
           let tx_isn = Wire_structs.Tcp_wire.get_tcp_sequence tcp in
           T.next_isn tx_isn ;

           Printf.printf "replaying first received tcp %d (%s:%d -> %s:%d):" !i (Ipaddr.V4.to_string dst) dst_port (Ipaddr.V4.to_string src) src_port; Cstruct.hexdump x ;
           i := succ !i ;
           Lwt.async (fun () -> T.input t ~listeners:(function 4433 -> Some server_cb | _ -> None) ~src:dst ~dst:src x);

           Printf.printf "replaying tcp %d (%s:%d -> %s:%d):" !i (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dst) dst_port; Cstruct.hexdump tcp ;
           i := succ !i ;
           Lwt.async (fun () -> T.input t ~listeners:(function 4433 -> Some server_cb | _ -> None) ~src ~dst tcp);
           first := None ;
           Lwt.return_unit
         | None ->
           if !not_initialised then
             begin
               (* we assume to have a SYN here! *)
               first := Some tcp ;
               not_initialised := false ;
               Printf.printf "received tcp %d (%s:%d -> %s:%d):" !i (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dst) dst_port; Cstruct.hexdump tcp ;
               i := succ !i ;
               (* setup client pcb *)
               I.set_ip ip src >|= fun () ->
               Lwt.async (fun () -> client t tcp src dst >>= function
                 | `Ok (flow, _) -> (Printf.printf "client flow is here\n%!" ;
                                     let rec recv () =
                                       T.read flow >>= function
                                       | `Ok buf -> client_data := buf :: !client_data ; recv ()
                                       | err -> Printf.printf "failed reading from client\n%!" ; Lwt.return_unit
                                     in
                                     recv ())
                 | _ -> Printf.printf "failed client\n%!" ; Lwt.return_unit) ;
             end
           else
             begin
               Printf.printf "received tcp %d (%s:%d -> %s:%d):" !i (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dst) dst_port; Cstruct.hexdump tcp ;
               i := succ !i ;
               Lwt.async (fun () -> T.input t ~listeners:(function 4433 -> Some server_cb | _ -> None) ~src ~dst tcp);
               Lwt.return_unit
             end )
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
                    ~ipv4:(fun buf -> recv_ip i t buf)
                    ~ipv6:(fun buf -> Lwt.return_unit) e
                 ) >>= fun () ->
      Lwt.return (p, e, i, t)
    in
    Lwt.async_exception_hook := (fun e ->
        Printf.printf "exception %s, backtrace\n%s"
          (Printexc.to_string e) (Printexc.get_backtrace ())) ;
    Tcp.(Log.enable Pcb.debug);
    Tcp.(Log.enable State.debug);
    Tcp.(Log.enable Segment.debug);
    setup_iface file ip nm >>= fun x ->
    play_pcap x >>= fun (p, e, i, t) ->
    (* test_send_arps p e u >>= fun result ->
       assert_equal ~printer `Success result; *)
    Printf.printf "finished... client data %d:" (List.length !client_data) ; List.iter Cstruct.hexdump !client_data ;
    Printf.printf "server data %d:" (List.length !server_data) ; List.iter Cstruct.hexdump !server_data ;
    Lwt.return_unit
end
