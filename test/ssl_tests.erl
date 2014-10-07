-module(ssl_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Tests Descriptions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
ssl_test_() ->
    {inorder, [
               ssl_tlsv1()
               ,ssl_tlsv1_1()
               ,ssl_tlsv1_2()
%               ,ssl_sslv3()

              ]}.
ssl_tlsv1() ->
    put(ssl_version, tlsv1),
    ssl_test_cases().
ssl_tlsv1_1() ->
    put(ssl_version, 'tlsv1.1'),
    ssl_test_cases().
ssl_tlsv1_2() ->
    put(ssl_version, 'tlsv1.2'),
    ssl_test_cases().
%ssl_sslv3() ->
%    put(ssl_version, sslv3),
%    ssl_test_cases().

ssl_test_cases() ->
    [
     {"Check SSL Connection no auth",
      {setup, fun default_setup/0, fun teardown/1, fun connect_no_auth/1}}
    ,{"Check SSL Connection no auth wrong CA",
      {setup, fun default_setup/0, fun teardown/1, fun connect_no_auth_wrong_ca/1}}
    ,{"Check SSL Connection Cert Auth",
      {setup, fun require_cert_setup/0, fun teardown/1, fun connect_cert_auth/1}}
    ,{"Check SSL Connection Cert Auth Without",
      {setup, fun require_cert_setup/0, fun teardown/1, fun connect_cert_auth_without/1}}
    ,{"Check SSL Connection Cert Auth Expired",
      {setup, fun require_cert_setup/0, fun teardown/1, fun connect_cert_auth_expired/1}}
    ,{"Check SSL Connection Cert Auth Revoked",
      {setup, fun require_cert_crl_setup/0, fun teardown/1, fun connect_cert_auth_revoked/1}}
    ,{"Check SSL Connection Cert Auth with CRL Check",
      {setup, fun require_cert_crl_setup/0, fun teardown/1, fun connect_cert_auth_crl/1}}
    ].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Setup Functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

default_setup() ->
    ensure_all_started(),
    {ok, ListenSocket} = ssl:listen(0, default_opts()),
    {ok, {_, Port}} = ssl:sockname(ListenSocket),
    {ListenSocket, Port, spawn(fun() -> accept(ListenSocket) end)}.

require_cert_setup() ->
    ensure_all_started(),
    {ok, ListenSocket} = ssl:listen(0, require_cert_opts()),
    {ok, {_, Port}} = ssl:sockname(ListenSocket),
    {ListenSocket, Port, spawn(fun() -> accept(ListenSocket) end)}.

require_cert_crl_setup() ->
    ensure_all_started(),
    {ok, ListenSocket} = ssl:listen(0, require_cert_crl_opts()),
    {ok, {_, Port}} = ssl:sockname(ListenSocket),
    {ListenSocket, Port, spawn(fun() -> accept(ListenSocket) end)}.

teardown({ListenSocket, _, _}) ->
    ssl:close(ListenSocket),
    application:stop(asn1),
    application:stop(public_key),
    application:stop(crypto),
    application:stop(ssl).

default_opts() ->
    [
     binary,
     {reuseaddr, true},
     {active, false},
     {packet, raw},
     {cacertfile, "../test/ssl/all-ca.crt"},
     {certfile, "../test/ssl/server.crt"},
     {keyfile, "../test/ssl/server.key"},
     {versions, [get(ssl_version)]}
    ].

require_cert_opts() ->
    [{verify, verify_peer},
     {fail_if_no_peer_cert, true} | default_opts()].

require_cert_crl_opts() ->
    CRLFile = "../test/ssl/crl.pem",
    [{verify_fun, {fun verify_ssl_peer/3, CRLFile}} | require_cert_opts()].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Actual Tests
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
connect_no_auth({_,Port,_}) ->
    {ok, ClientSocket} = ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {cacertfile, "../test/ssl/test-root-ca.crt"}]),
    ?_assertEqual(ok, echo_test(ClientSocket)).

connect_no_auth_wrong_ca({_,Port,_}) ->
    ?_assertEqual({error,{tls_alert,"unknown ca"}},
                  ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-alt-ca.crt"}])).

connect_cert_auth({_,Port,_}) ->
    {ok, ClientSocket} = ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-root-ca.crt"},
                               {certfile, "../test/ssl/client.crt"},
                               {keyfile, "../test/ssl/client.key"}]),
    ?_assertEqual(ok, echo_test(ClientSocket)).

connect_cert_auth_without({_,Port,_}) ->
    ?_assertEqual({error,{tls_alert,"handshake failure"}},
                  ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-root-ca.crt"}])).

connect_cert_auth_expired({_,Port,_}) ->
    ?_assertEqual({error,{tls_alert,"certificate expired"}},
                  ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-root-ca.crt"},
                               {certfile, "../test/ssl/client-expired.crt"},
                               {keyfile, "../test/ssl/client.key"}])).

connect_cert_auth_revoked({_,Port,_}) ->
    ?_assertEqual({error,{tls_alert,"certificate revoked"}},
                  ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-root-ca.crt"},
                               {certfile, "../test/ssl/client-revoked.crt"},
                               {keyfile, "../test/ssl/client.key"}])).

connect_cert_auth_crl({_,Port,_}) ->
    {ok, ClientSocket} = ssl:connect("localhost", Port,
                              [binary, {active, false}, {packet, raw},
                               {verify, verify_peer},
                               {cacertfile, "../test/ssl/test-root-ca.crt"},
                               {certfile, "../test/ssl/client.crt"},
                               {keyfile, "../test/ssl/client.key"}]),
    ?_assertEqual(ok, echo_test(ClientSocket)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Helper
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
accept(ListenSocket) ->
    {ok, Socket} = ssl:transport_accept(ListenSocket),
    case ssl:ssl_accept(Socket) of
        ok ->
            {ok, <<L>>} = ssl:recv(Socket, 1),
            {ok, Msg} = ssl:recv(Socket, L),
            ok = ssl:send(Socket, <<L, Msg/binary>>);
        {error, _Reason} ->
            ssl:close(Socket)
    end.

echo_test(ClientSocket) ->
    Msg = <<"hello world">>,
    ok = ssl:send(ClientSocket, <<(byte_size(Msg)), Msg/binary>>),
    {ok, <<L>>} = ssl:recv(ClientSocket, 1),
    {ok, Msg} = ssl:recv(ClientSocket, L),
    ok = ssl:close(ClientSocket).

verify_ssl_peer(_, {bad_cert, _} = Reason, _) ->
    {fail, Reason};
verify_ssl_peer(_,{extension, _}, CRLFile) ->
    {unknown, CRLFile};
verify_ssl_peer(_, valid, CRLFile) ->
    {valid, CRLFile};
verify_ssl_peer(Cert, valid_peer, CRLFile) ->
    case public_key:pkix_is_self_signed(Cert) of
        true ->
            {fail, is_self_signed};
        false ->
            case check_crl(CRLFile, Cert) of
                true ->
                    {valid, CRLFile};
                false ->
                    {fail, {bad_cert, cert_revoked}}
            end
    end.

check_crl(File, #'OTPCertificate'{tbsCertificate=TBSCert}) ->
    {ok, Bin} = file:read_file(File),
    SerialNr = TBSCert#'OTPTBSCertificate'.serialNumber,
    Serials =
    lists:flatten([begin
                       CRL = public_key:pem_entry_decode(E) ,
                       #'TBSCertList'{revokedCertificates=Revoked} = CRL#'CertificateList'.tbsCertList,
                       [SNr || #'TBSCertList_revokedCertificates_SEQOF'{userCertificate=SNr} <- Revoked]
                   end || E <- public_key:pem_decode(Bin)]),
    not lists:member(SerialNr, Serials).

ensure_all_started() ->
    %% application:ensure_all_started(ssl) not available on older versions
    application:start(crypto),
    application:start(asn1),
    application:start(public_key),
    application:start(ssl).
