-module(erlang_ssl_tester_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    erlang_ssl_tester_sup:start_link().

stop(_State) ->
    ok.
