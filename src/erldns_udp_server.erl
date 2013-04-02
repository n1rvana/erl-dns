-module(erldns_udp_server).
-behavior(gen_server).

% API
-export([start_link/2]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).
-define(NUM_WORKERS, 2).

-record(state, {port, socket, workers}).

%% Public API
start_link(Name, InetFamily) ->
  gen_server:start_link({local, Name}, ?MODULE, [InetFamily], []).

%% gen_server hooks
init([InetFamily]) ->
  Port = erldns_config:get_port(),
  {ok, Socket} = start(Port, InetFamily),
  {ok, #state{port = Port, socket = Socket, workers = make_workers([], [Socket], InetFamily)}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info(timeout, State) ->
  lager:info("~p timed out", [?MODULE]),
  {noreply, State};
handle_info({udp, _Socket, Host, Port, _Bin}, State) ->
  lager:info("~p received a packet when it should not (host=~p port=~p)", [?MODULE, Host, Port]),
  {noreply, State}; 
handle_info(Message, State) ->
  lager:debug("Received unknown message: ~p", [Message]),
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Internal functions
%% Start a UDP server.
start(Port, InetFamily) ->
  lager:info("Starting UDP server for ~p on port ~p", [InetFamily, Port]),
  case gen_udp:open(Port, [binary, {active, false}, {ip, erldns_config:get_address(InetFamily)}, InetFamily]) of
    {ok, Socket} -> 
      lager:info("UDP server (~p) opened socket: ~p", [InetFamily, Socket]),
      {ok, Socket};
    {error, eacces} ->
      lager:error("Failed to open UDP socket. Need to run as sudo?"),
      {error, eacces}
  end.

make_workers(Workers, Args, InetFamily) ->
  make_workers(Workers, Args, InetFamily, 1).
make_workers(Workers, Args, InetFamily, N) when N < ?NUM_WORKERS ->
  {ok, WorkerPid} = erldns_udp_worker:start_link(N, InetFamily, Args),
  erldns_udp_worker:listen(N, InetFamily),
  make_workers([Workers|WorkerPid], Args, InetFamily, N + 1);
make_workers(Workers, _Args, _InetFamily, _) ->
  Workers.
