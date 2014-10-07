-module(eunit_ssl_reporter).
-behaviour(eunit_listener).
% EUnit Callbacks
-export([start/0,
         start/1,
         init/1,
         handle_begin/3,
         handle_end/3,
         handle_cancel/3,
         terminate/2]).

-record(state, {cases=[], opts=[]}).

start() ->
    start([]).
start(Options) ->
    eunit_listener:start(?MODULE, Options).
init(Options) ->
    #state{opts=Options}.

handle_begin(_Type, _Data, State) ->
    State.
handle_end(test, Data, State) ->
    State#state{cases = State#state.cases ++ [Data]};
handle_end(_Type, _Data, State) ->
    State.
handle_cancel(group, Data, State) ->
    State#state{cases = State#state.cases ++ [Data]};
handle_cancel(_Type, _Data, State) ->
    State.
terminate({ok, _Result}, #state{cases = Cases}) ->
    Res =
    lists:foldl(
      fun(C, Acc) ->
              Status =
              case proplists:get_value(status, C) of
                  ok -> ok;
                  _ -> error
              end,
              case proplists:get_value(source, C) of
                  {_, F, _} ->
                      [{F,Status}|Acc];
                  _ ->
                      Acc
              end

      end, [], Cases),
    io:format("results ~p~n", [Res]).
