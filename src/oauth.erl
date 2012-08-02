%%%-------------------------------------------------------------------
%%% @author egobrain <>
%%% @copyright (C) 2012, egobrain
%%% @doc
%%%
%%% @end
%%% Created : 28 Apr 2012 by egobrain <>
%%%-------------------------------------------------------------------
-module(oauth).

-include("log.hrl").
-include("oauth.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% OAUTH API
-export([new_client/0,valid_client_authorization/1]).

-export([valid_authorize_req/1,authorize/2,
	 format_authrize_resp_uri/3,
	 format_authrize_error_uri/3]).

-export([token/2,
	 format_token_resp_json/1,
	 format_token_resp_uri/3,
	 format_token_error_json/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {table}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% = Authorize =======================================================


-spec valid_authorize_req(#auth_req{}) ->
    {ok,AuthReq :: #auth_req{}} | {error, #auth_error{}}.
valid_authorize_req(#auth_req{response_type=undefined,state=State}) ->
    {error,#auth_error{error=invalid_request,
		error_description= <<"response_type REQUIRED">>,
		state=State
	       }};
valid_authorize_req(#auth_req{client_id=undefined,state=State}) ->
    {error,#auth_error{error=invalid_request,
		error_description= <<"client_id REQUIRED">>,
		state=State
	       }};
valid_authorize_req(#auth_req{redirect_uri=undefined}) ->
    {error,#auth_error{
       error= invalid_redirect_uri,
       error_description = <<"redirect_uri is invalid">>
      }};
valid_authorize_req(#auth_req{response_type= Code,
			  client_id=Client_id,
			  state=State
			 } = AuthReq)
  when Code =:= <<"code">> orelse Code =:= <<"token">> ->
    case find_client(Client_id) of
	{ok,_} -> {ok,AuthReq};
	undefined ->
	   {error,#auth_error{error=unauthorized_client,
			error_description= <<"Client is not authorized">>,
			state=State
		       }}
    end;
valid_authorize_req(#auth_req{response_type=Request_type,state=State}) ->
    {error,#auth_error{error=unsupported_response_type,
		       error_description= <<"Unknown response_type \"",Request_type/binary>>,
		state=State
	  }}.

-spec authorize(#auth_req{},Grant :: any()) ->  {ok,AuthResp :: #auth_resp{}}.
authorize(#auth_req{response_type= <<"code">>,
		    client_id=Client_id,
		    redirect_uri=Redirect_uri,
		    scope=Scope,
		    state=State
		   },Grant) ->
    Code = random_string(),
    % @todo format {Scope,Grant} as Generic data type
    save_token({Code,Client_id,Redirect_uri},{Scope,Grant}),
    {ok,#auth_resp{code=Code,
	       state=State
	      }};
authorize(#auth_req{response_type= <<"token">>,
		    scope=Scope,
		    state=State
		   },Grant) ->
    Token=random_string(),
    Created=get_timestamp(),
    ExpiresIn = ?EXPIRES_IN,
    AccessToken = #access_token{access_token=Token,
				created=Created,
				expires_in=ExpiresIn,
				scope=Scope,
				grant=Grant
			       },
    save_access_token(AccessToken),
    {ok,#token_resp{access_token  = Token,
		    token_type    = <<"bearer">>,
		    expires_in    = ExpiresIn,
		    scope         = Scope,
		    state         = State
		   }}.


-spec format_authrize_resp_uri(#auth_req{},#auth_resp{},URLEncode :: function()) -> binary().
format_authrize_resp_uri(#auth_req{redirect_uri=RedirectURI},#auth_resp{code=Code,state=State},Encoder) ->
    URI = <<RedirectURI/binary,"?">>,
    add_params_to_uri(URI,[{<<"code">>,Code},
			   {<<"state">>,State}],Encoder).

-spec format_authrize_error_uri(#auth_req{},#auth_error{},URLEncode :: function()) -> binary().
format_authrize_error_uri(#auth_req{redirect_uri=RedirectURI},#auth_error{error=ErrorAtom,
									  error_description=Description,
									  error_uri=ErrorURI
									 },Encoder) ->
    URI = <<RedirectURI/binary,"?">>,
    add_params_to_uri(URI,[{<<"error">>,ErrorAtom},
			   {<<"error_description">>,Description},
			   {<<"error_uri">>,ErrorURI}],Encoder).	

%% = Token ===========================================================

-spec token(#token_req{},Client_id :: binary()) -> {ok,#token_resp{}} | {error,#token_error{}}.
token(#token_req{grant_type=undefined},_Client_ID) ->
    {error,#token_error{
       error=invalid_request,
       error_description = <<"grant_type REQUIRED">>
      }};
token(#token_req{grant_type= <<"authorization_code">>,code=undefined},_Client_ID) ->
    {error,#token_error{
       error=invalid_request,
       error_description = <<"code REQUIRED">>
      }};
token(#token_req{grant_type= <<"authorization_code">>,redirect_uri=undefined},_Client_ID) ->
    {error,#token_error{
       error= invalid_redirect_uri,
       error_description = <<"redirect_uri is invalid">>
      }};
token(#token_req{grant_type= <<"authorization_code">>,
		 code=Code,
		 redirect_uri=Redirect_uri
		},Client_ID) ->
    Token = {Code,Client_ID,Redirect_uri},
    case find_token(Token) of
	{ok,{Scope,Grant}} ->
	    TokenStr=random_string(),
	    Created=get_timestamp(),
	    ExpiresIn = ?EXPIRES_IN,
	    RefreshToken = random_string(),
	    AccessToken = #access_token{access_token=TokenStr,
					token_type= <<"bearer">>,
					created=Created,
					expires_in=ExpiresIn,
					refresh_token=RefreshToken,
					scope=Scope,
					
					grant=Grant,
					client_id=Client_ID
				       },
	    save_access_token(AccessToken,Token),
	    {ok,#token_resp{access_token  =  TokenStr,
			    token_type        =  <<"bearer">>,
			    expires_in        =  ExpiresIn,
			    refresh_token     =  RefreshToken,
			    scope             =  Scope
		       }};
	undefined ->
	    {error,#token_error{error=invalid_grant,
			 error_description= <<"grant is Invalid">>
			}}
    end;
token(#token_req{grant_type= <<"refresh_token">>,refresh_token=undefined},_Client_ID) ->
    {error,#token_error{
       error=invalid_request,
       error_description = <<"refresh_token REQUIRED">>
      }};
token(#token_req{grant_type= <<"refresh_token">>,refresh_token=RefreshToken,scope=ReqScope},Client_ID) ->
    case get_access_token_by_refresh(RefreshToken,Client_ID) of
	{ok,#access_token{access_token=AccessToken,
			  token_type=TokenType,
			  expires_in=ExpiresIn,
			  refresh_token=NewRefreshToken,
			  scope=Scope
			 }} ->

	    case ReqScope=:=Scope orelse ReqScope =:= undefined of
		true ->
		    {ok,#token_resp{access_token  =  AccessToken,
				    token_type    =  TokenType,
				    expires_in    =  ExpiresIn,
				    refresh_token =  NewRefreshToken,
				    scope         =  Scope
				   }};
		false ->
		    {error,#token_error{error=invalid_scope,
					error_description = <<"Scope is invalid">>
				       }}
	    end;		
	undefined ->
	    {error,#token_error{
	       error=invalid_grant,
	       error_description = <<"Unknown refresh_token">>
	      }}
    end;
token(#token_req{grant_type=Grant_type},_Client_ID) ->
    {error,#token_error{
       error=invalid_grant_type,
       error_description = <<"Unknown grant_type ",Grant_type/binary>>
      }}.


-spec format_token_resp_json(Token :: #token_resp{}) ->  iolist().
format_token_resp_json(#token_resp{} = Token) ->
    format_json(Token).

-spec format_token_resp_uri(#auth_req{},Token :: #token_resp{},Encoder :: function()) ->  iolist().
format_token_resp_uri(#auth_req{redirect_uri=RedirectURI},
		      #token_resp{access_token=AccessToken,
				  token_type=TokenType,
				  expires_in=ExpiresIn,
				  scope=Scope,
				  state=State
				 },Encoder) ->
    URI = <<RedirectURI/binary,"#">>,
    add_params_to_uri(URI,
		      [{<<"access_token">>,AccessToken},
		       {<<"token_type">>,TokenType},
		       {<<"expires_in">>,ExpiresIn},
		       {<<"scope">>,Scope},
		       {<<"state">>,State}
		      ],Encoder).		

-spec format_token_error_json(TokenError :: #token_error{}) ->  iolist().
format_token_error_json(#token_error{} = TokenError) ->
    format_json(TokenError).

%% = Client ==========================================================

-spec valid_client_authorization(ClienAuthData::#oauth_client{}) ->  {ok,Client_ID::binary()} | {error,unauth}.
valid_client_authorization(#oauth_client{client_id=undefiend}) -> false;
valid_client_authorization(#oauth_client{client_secret=undefiend}) -> false;
valid_client_authorization(#oauth_client{client_id=Client_ID,
				         client_secret=Client_secret
				        }) ->
    case find_client(Client_ID) of
	{ok,Client_secret} -> {ok,Client_ID};
	_ -> {error,unauth}
    end.

-spec new_client() -> #oauth_client{}.
new_client() ->
    Client_ID = random_string(),
    Secret = random_string(),
    save_client(Client_ID,Secret),
    #oauth_client{client_id = Client_ID,
		  client_secret = Secret
		 }.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    Table = new_table(),
    {ok, #state{table=Table}}.

%% @private

handle_call({save,Tag,Key,Value}, _From, #state{table=Table} = State) ->
    save(Tag,Key,Value,Table),
    {reply, ok, State};

handle_call({find,Tag,Key}, _From, #state{table=Table} = State) ->
    Result = find(Tag,Key,Table),
    {reply, Result, State};

% handle_call({delete,Tag,Key}, _From, #state{table=Table} = State) ->
%     Result = delete(Tag,Key,Table),
%     {reply, Result, State};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

random_string() ->
    list_to_binary(uuid:to_string(uuid:uuid1())).

get_timestamp() ->
    {Mega, Secs, _} = now(),
    Mega*1000000 + Secs.
 

add_params_to_uri(Uri,Params,Encoder) ->
    Adder = fun({_Name,undefined},Acc) -> Acc;
	       ({Name,Value},Acc) ->
		    ValueEncoded = case Value of
				       _ when is_binary(Value) ->
					   Encoder(Value);
				       _ when is_atom(Value) ->
					   Encoder(list_to_binary(atom_to_list(Value)));
				       _ when is_integer(Value) ->
					   list_to_binary(integer_to_list(Value))
				   end,
		    NewAcc = case Acc of
				 <<>> -> Acc;
				 _ -> <<Acc/binary,"&">>
					  end,
		    <<NewAcc/binary,Name/binary,"=",ValueEncoded/binary>>
            end,
    ParamsBin = lists:foldl(Adder,<<>>,Params),
    <<Uri/binary,ParamsBin/binary>>.


format_json(Record) ->
    Proplist = oauth_rd:to_proplist(Record),
    Filtered = lists:filter(fun({_,undefined}) -> false;
			       (_) ->true
			    end,
			    Proplist),
    mochijson3_fork:encode({struct,Filtered}).
    


%%%= Internal ========================================================

save(Tag,Key,Value) ->
    gen_server:call(?MODULE,{save,Tag,Key,Value}).

find(Tag,Key) ->
    gen_server:call(?MODULE,{find,Tag,Key}).

%%%= DB interface ====================================================

-spec new_table() -> Table :: term().
new_table() ->
    ets:new(?MODULE,[]).

save(access_token,AccessToken,undefined,Table) ->
    ets:insert(Table,{{access_token,AccessToken#access_token.access_token},AccessToken}),
    ok;
save(access_token,AccessToken,PrevTaggedToken,Table) ->
    ets:insert(Table,{{access_token,AccessToken#access_token.access_token},AccessToken}),
    ets:delete(Table,PrevTaggedToken),
    ok;
save(Tag,Key,Value,Table) ->
    ets:insert(Table,{{Tag,Key},Value}),
    ok.

find(refresh_token,{RefreshToken,Client_ID},Table) ->
    Q = ets:fun2ms(fun({{access_token,_},#access_token{refresh_token=RT,client_id=CID
						      }} = R) when RT=:=RefreshToken andalso
								   CID=:=Client_ID -> R end),
    case ets:select(Table,Q) of
	[{Key,AccessToken}|_] ->
	    NewAccessTokenStr = random_string(),
	    NewRefreshTokenStr = random_string(),
	    NewAccessToken = AccessToken#access_token{
			       access_token=NewAccessTokenStr,
			       created=get_timestamp(),
			       refresh_token=NewRefreshTokenStr},
	    ets:delete(Table,Key),
	    ets:insert(Table,{{access_token,NewAccessTokenStr},NewAccessToken}),
	    {ok,NewAccessToken};
        [] ->
	    undefined
    end;       
find(Tag,Key,Table) ->
    case ets:lookup(Table,{Tag,Key}) of
	[{_,Value}|_] ->
	    {ok,Value};
	_ ->
	    undefined
    end.


%%%= Internal usage ==================================================

save_client(ClientID,Data) ->
    save(client_id,ClientID,Data).

find_client(ClientID) ->
    find(client_id,ClientID).

save_token(TokenID,Grant) ->
    save(token,TokenID,Grant).

find_token(TokenID) ->
    find(token,TokenID).

get_access_token_by_refresh(TokenID,ClientID) ->
    find(refresh_token,{TokenID,ClientID}).

save_access_token(AccessToken,PrevToken) ->
    save(access_token,AccessToken,{token,PrevToken}).

save_access_token(AccessToken) ->
    save(access_token,AccessToken,undefined).
    
