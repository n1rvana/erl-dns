-module(erldns_udp_worker).

-include("dns.hrl").

-behaviour(gen_server).

-export([start_link/3, listen/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% Internal API
-export([handle_query/4]).

-record(state, {socket}).

-define(MAX_PACKET_SIZE, 512).

start_link(Id, InetFamily, [Socket]) ->
  lager:info("Starting worker ~p:~p with socket ~p", [Id, InetFamily, Socket]),
  gen_server:start_link({local, list_to_atom("erldns_udp_worker" ++ [Id] ++ atom_to_list(InetFamily))}, ?MODULE, [Socket], []).

listen(Id, InetFamily) ->
  gen_server:cast(list_to_atom("erldns_udp_worker" ++ [Id] ++ atom_to_list(InetFamily)), {listen}). 

init([Socket]) ->
  {ok, #state{socket = Socket}}.

handle_call(_Request, _From, State) ->
  {reply, ok, State}.

handle_cast({listen}, State) ->
  receive_next(State#state.socket),
  {noreply, State};
handle_cast(_Msg, State) ->
  {noreply, State}.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

receive_next(Socket) ->
  case gen_udp:recv(Socket, 0) of
    {ok, {Address, Port, Packet}} ->
      erldns_metrics:measure(Address, ?MODULE, handle_query, [Socket, Address, Port, Packet]);
    {error, ealready} ->
      ok;
    {error, Reason} ->
      lager:error("Error reading packet: ~p", [Reason])
  end,
  receive_next(Socket).

%% Handle DNS query that comes in over UDP
handle_query(Socket, Host, Port, Bin) ->
  lager:debug("handle_udp_dns_query(~p ~p ~p)", [Socket, Host, Port]),
  %% TODO: measure
  case dns:decode_message(Bin) of
    {truncated, _} -> lager:debug("received bad request from ~p", [Host]);
    {formerr, _, _} -> lager:debug("formerr bad request from ~p", [Host]);
    DecodedMessage ->
      Response = erldns_metrics:measure(none, erldns_handler, handle, [DecodedMessage, Host]),
      case erldns_encoder:encode_message(Response, [{'max_size', max_payload_size(Response)}]) of
        {false, EncodedMessage} -> gen_udp:send(Socket, Host, Port, EncodedMessage);
        {true, EncodedMessage, Message} when is_record(Message, dns_message)->
          lager:debug("Leftover: ~p", [Message]),
          gen_udp:send(Socket, Host, Port, EncodedMessage);
        {false, EncodedMessage, TsigMac} ->
          lager:debug("TSIG mac: ~p", [TsigMac]),
          gen_udp:send(Socket, Host, Port, EncodedMessage);
        {true, EncodedMessage, TsigMac, Message} ->
          lager:debug("TSIG mac: ~p; Leftover: ~p", [TsigMac, Message]),
          gen_udp:send(Socket, Host, Port, EncodedMessage)
      end
  end.

%% Determine the max payload size by looking for additional
%% options passed by the client.
max_payload_size(Message) ->
  case Message#dns_message.additional of
    [Opt|_] when is_record(Opt, dns_optrr) ->
      case Opt#dns_optrr.udp_payload_size of
        [] -> ?MAX_PACKET_SIZE;
        _ -> Opt#dns_optrr.udp_payload_size
      end;
    _ -> ?MAX_PACKET_SIZE
  end.
