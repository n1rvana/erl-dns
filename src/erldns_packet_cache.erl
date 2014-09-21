%% Copyright (c) 2012-2013, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc A basic packet cache that is used to avoid multiple lookups for the
%% same question received within the cache TTL.
%%
%% The cache is swept for old cache data at regular intervals.
-module(erldns_packet_cache).

-behavior(gen_server).

% API
-export([start_link/0, get/1, get/2, put/2, sweep/0, clear/0, stop/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).
-define(ENABLED, true).
-define(SWEEP_INTERVAL, 1000 * 60 * 3). % Every 3 minutes

-record(state, {
    ttl :: non_neg_integer(),
    tref :: timer:tref()
  }).

% Public API

%% @doc Start the cache.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Try to retrieve a cached response for the given question.
-spec get(dns:question()) -> {ok, dns:message()} | {error, cache_expired} | {error, cache_miss}.
get(Question) ->
  get(Question, unknown).

%% @doc Try to retrieve a cached response for the given question sent
%% by the given host.
-spec get(dns:question(), dns:ip()) -> {ok, dns:message()} | {error, cache_expired} | {error, cache_miss}.
get(Question, _Host) ->
  case ets:lookup(packet_cache, Question) of
    [{Question, {Response, ExpiresAt}}] ->
      case timestamp() > ExpiresAt of
        true ->
          folsom_metrics:notify(cache_expired_meter, 1),
          {error, cache_expired};
        false ->
          folsom_metrics:notify(cache_hit_meter, 1),
          {ok, Response}
      end;
    _ ->
      folsom_metrics:notify(cache_miss_meter, 1),
      {error, cache_miss}
  end.

%% @doc Put the response in the cache for the given question.
-spec put(dns:question(), dns:message()) -> ok.
put(Question, Response) ->
  case ?ENABLED of
    true ->
      %lager:debug("Set packet in cache for ~p", [Question]),
      gen_server:call(?SERVER, {set_packet, [Question, Response]});
    _ ->
      %lager:debug("Packet cache not enabled (Q: ~p)", [Question]),
      ok
  end.

%% @doc Remove all old cached packets from the cache.
-spec sweep() -> any().
sweep() ->
  gen_server:cast(?SERVER, sweep).

%% @doc Clean the cache
-spec clear() -> any().
clear() ->
  gen_server:cast(?SERVER, clear).

%% @doc Stop the cache
-spec stop() -> any().
stop() ->
  gen_server:call(?SERVER, stop).

%% Gen server hooks
-spec init([non_neg_integer()]) -> {ok, #state{}}.
init([]) ->
  init([20]);
init([TTL]) ->
  ets:new(packet_cache, [set, named_table]),
  {ok, Tref} = timer:apply_interval(?SWEEP_INTERVAL, ?MODULE, sweep, []),
  {ok, #state{ttl = TTL, tref = Tref}}.

handle_call({set_packet, [Question, Response]}, _From, State) ->
  ets:insert(packet_cache, {Question, {Response, timestamp() + State#state.ttl}}),
  {reply, ok, State};

handle_call(stop, _From, State) ->
  {stop, normal, ok, State}.

handle_cast(sweep, State) ->
  Keys = ets:select(packet_cache, [{{'$1', {'_', '$2'}}, [{'<', '$2', timestamp() - 10}], ['$1']}]),
  lists:foreach(fun(K) -> ets:delete(packet_cache, K) end, Keys),
  {noreply, State};

handle_cast(clear, State) ->
  ets:delete_all_objects(packet_cache),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ets:delete(packet_cache),
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

timestamp() ->
  {TM, TS, _} = os:timestamp(),
  (TM * 1000000) + TS.
