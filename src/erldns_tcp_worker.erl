-module(erldns_tcp_worker).

-include("dns.hrl").

-behaviour(gen_server).
-behaviour(poolboy_worker).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {}).

start_link([]) ->
  gen_server:start_link(?MODULE, [], []).

init([]) ->
  {ok, #state{}}.

handle_call({tcp_query, Socket, Bin}, _From, State) ->
  {reply, handle_tcp_dns_query(Socket, Bin), State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}. 
handle_cast(_Msg, State) ->
  {noreply, State}.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% Handle DNS query that comes in over TCP
handle_tcp_dns_query(Socket, Packet) ->
  lager:debug("handle_tcp_dns_query(~p)", [Socket]),
  %% TODO: measure 
  <<_Len:16, Bin/binary>> = Packet,
  {ok, {Address, _Port}} = inet:peername(Socket),
  case Bin of
    <<>> -> ok;
    _ ->
      case dns:decode_message(Bin) of
        {truncated, _} -> lager:info("received bad request from ~p", [Address]);
        DecodedMessage ->
          Response = erldns_metrics:measure(none, erldns_handler, handle, [DecodedMessage, Address]),
          case erldns_encoder:encode_message(Response) of
            {false, EncodedMessage} ->
              send_tcp_message(Socket, EncodedMessage);
            {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
              lager:debug("Leftover: ~p", [Message]),
              send_tcp_message(Socket, EncodedMessage);
            {false, EncodedMessage, TsigMac} ->
              lager:debug("TSIG mac: ~p", [TsigMac]),
              send_tcp_message(Socket, EncodedMessage);
            {true, EncodedMessage, TsigMac, Message} ->
              lager:debug("TSIG mac: ~p; Leftover: ~p", [TsigMac, Message]),
              send_tcp_message(Socket, EncodedMessage)
          end
      end
  end,
  gen_tcp:close(Socket).

send_tcp_message(Socket, EncodedMessage) ->
  BinLength = byte_size(EncodedMessage),
  TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
  gen_tcp:send(Socket, TcpEncodedMessage).
