open V1_LWT
open Lwt

module Main (C : CONSOLE) (K : KV_RO) (L : KV_RO) = struct
  module P = Netif.Make(K)(OS.Time)
  module E = Ethif.Make(P)
  module I = Ipv4.Make(E)(Clock)(OS.Time)
  module T = Tcp.Flow.Make(I)(OS.Time)(Clock)(Random)
  (*  module Stack = Tcpip_stack_direct.Make(C)(OS.Time)(Random)(Netif)(Stackv41_E)(Stackv41_I)(Stackv41_U)(Stackv41_T) *)
  module X509 = Tls_mirage.X509(L)(Clock)

  let file = "tlssession.pcap"

  (* guess that is ok... *)
  let ip = Ipaddr.V4.of_string_exn "1.1.1.1"
  let nm = Ipaddr.V4.of_string_exn "0.0.0.0"

  let start c k keys =

    let or_error c name fn t =
      fn t >>= function
      | `Error e -> fail (Failure ("Error starting " ^ name))
      | `Ok t -> return t
    in

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

    let log = C.log c in

    let server_cb flow =
      log "server callback" ;
      let rec recv () =
        T.read flow >>= function
        | `Ok buf -> server_data := buf :: !server_data ; recv ()
        | err -> Lwt.return_unit
      in
      recv ()
    in
    let client_cb flow =
      log "client callback" ;
      let rec recv () =
        T.read flow >>= function
        | `Ok buf -> client_data := buf :: !client_data ; recv ()
        | _ -> Lwt.return_unit
      in
      recv ()
    in

    let first : Cstruct.t option ref = ref None in
    let flow = ref None in
    let flow_matches_packet (f_s, f_s_p, f_d, f_d_p) src src_port dst dst_port =
      (Ipaddr.V4.compare f_s src = 0 &&
       Ipaddr.V4.compare f_d dst = 0 &&
       f_s_p = src_port && f_d_p = dst_port) ||
      (Ipaddr.V4.compare f_s dst = 0 &&
       Ipaddr.V4.compare f_d src = 0 &&
       f_s_p = dst_port && f_d_p = src_port)
    in
    let frameno = ref 0 in

    let recv_ip ip t buf =
      frameno := succ !frameno ;
      let count = !frameno in
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
        let flow_to_string (src, src_port, dst, dst_port) =
          Printf.sprintf "%s:%d -> %s:%d"
            (Ipaddr.V4.to_string src) src_port (Ipaddr.V4.to_string dst) dst_port
        in
        let log_packet prefix flow =
          log (prefix ^ ": " ^ flow_to_string flow)
        in
        (match !flow, !first with
         | None, None ->
           (* we demand a SYN here! *)
           (match Wire_structs.Tcp_wire.(get_syn tcp, get_fin tcp, get_ack tcp, get_rst tcp) with
            | true, false, false, false ->
              first := Some tcp ;
              flow := Some (src, src_port, dst, dst_port) ;

              (* setup stack: IP address and arp entries *)
              I.set_ip ip src >>= fun () ->
              let insert_arp ipaddr =
                let frame = Cstruct.create 42 in (* length of an ARP frame + ethernet *)
                Cstruct.BE.set_uint16 frame 20 2 ; (* ARP reply *)
                Cstruct.BE.set_uint32 frame 28 (Ipaddr.V4.to_int32 ipaddr) ; (* sender protocol address *)
                I.input_arpv4 ip frame
              in
              insert_arp src >>= fun () ->
              insert_arp dst >|= fun () ->

              (* setup client pcb *)
              Lwt.async (fun () -> client t tcp src dst >>= function
                | `Ok (flow, _) -> client_cb flow
                | _ -> log "failed client" ; Lwt.return_unit)
            | _ -> log "skipping first TCP frame (not a SYN only)" ; Lwt.return_unit)
         | Some flow, Some x when flow_matches_packet flow src src_port dst dst_port ->
           (* tcp better be a synack, and coming from server to client *)
           (* for the server side, we prepare a special sequence number *)
           let tx_isn = Wire_structs.Tcp_wire.get_tcp_sequence tcp in
           T.next_isn tx_isn ;

           let (_, _, _, server_port) = flow in
           log_packet (Printf.sprintf "frame %d" count) (dst, dst_port, src, src_port) ;
           Lwt.async (fun () -> T.input t ~listeners:(function x when x = server_port -> Some server_cb | _ -> None) ~src:dst ~dst:src x);

           log_packet (Printf.sprintf "frame %d" count) (src, src_port, dst, dst_port) ;
           Lwt.async (fun () -> T.input t ~listeners:(function x when x = server_port -> Some server_cb | _ -> None) ~src ~dst tcp);
           first := None ;
           Lwt.return_unit
         | Some flow, None when flow_matches_packet flow src src_port dst dst_port ->
           let (_, _, _, server_port) = flow in
           log_packet (Printf.sprintf "frame %d" count) (src, src_port, dst, dst_port) ;
           Lwt.async (fun () -> T.input t ~listeners:(function x when x = server_port -> Some server_cb | _ -> None) ~src ~dst tcp);
           Lwt.return_unit
         | _ -> log "skipping unmatched TCP frame" ; Lwt.return_unit)
      | _ -> log "skipping unmatched frame" ; Lwt.return_unit
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
      I.set_ip i ip >>= fun () ->
      I.set_ip_netmask i nm >>= fun () ->
      Lwt.return (p, e, i, t)
    in

    let play_pcap (p, e, i, t) =
      P.listen p (E.input
                    ~arpv4:(fun buf -> Lwt.return_unit)
                    ~ipv4:(fun buf -> recv_ip i t buf)
                    ~ipv6:(fun buf -> Lwt.return_unit) e)
      >|= fun () ->
      (p, e, i, t)
    in

    Lwt.async_exception_hook := (fun e ->
        log (Printf.sprintf "exception %s, backtrace\n%s"
               (Printexc.to_string e) (Printexc.get_backtrace ()))) ;
    Tcp.(Log.enable Pcb.debug);
    Tcp.(Log.enable State.debug);
    Tcp.(Log.enable Segment.debug);
    setup_iface file ip nm >>= fun x ->
    play_pcap x >>= fun (p, e, i, t) ->

    log (Printf.sprintf "finished... %d client data %d server data" (List.length !client_data) (List.length !server_data)) ;

    let open Tls in
    (* what is our config? and initial state! *)
    let rec mix c s =
      match c, s with
      | [], [] -> []
      | [c], [] ->
        ( match Engine.separate_records c with
          | Ok (xs, rest) ->
            assert (Cstruct.len rest = 0) ;
            List.map (fun x -> `RecordIn x) xs )
      | c::cs, s::ss ->
        match Engine.separate_records c, Engine.separate_records s with
        | Ok (xs, rest), Ok (ys, rest') ->
          assert (Cstruct.len rest = 0) ;
          assert (Cstruct.len rest' = 0) ;
          let c = List.map (fun x -> `RecordIn x) xs in
          let s = List.map (fun (hdr, data) -> `RecordOut (hdr.Core.content_type, data)) ys in
          c @ s @ mix cs ss
        | _ -> assert false
    in

    let trace = mix (List.rev !server_data) (List.rev !client_data) in
    log ("tracce is " ^ string_of_int (List.length trace)) ;
    let t =
      String.concat "\n"
        (List.map
           (fun x -> Sexplib.Sexp.to_string_hum (Tracer_common.sexp_of_trace x))
           trace)
    in
    log ("trace is: " ^ t) ;

    X509.certificate keys `Default >>= fun (cert, priv) ->
    let config = Tls.Config.server ~certificates:(`Single (cert, priv)) () in
    let state = Engine.server config in

    let r = Tracer_replay.replay state state [] trace 0 None true in
    log ("trace result: " ^ (Sexplib.Sexp.to_string_hum (Tracer_replay.sexp_of_ret r))) ;

    Lwt.return_unit
end
