%%%-------------------------------------------------------------------
%%% @author egobrain <>
%%% @copyright (C) 2012, egobrain
%%% @doc
%%%
%%% @end
%%% Created : 26 Apr 2012 by egobrain <>
%%%-------------------------------------------------------------------
-module(oauth_cowboy_handler).
-include("log.hrl").
-include("oauth.hrl").

-record(state,{path = [],method :: atom(), module :: atom()}).

-export([init/3,handle/2,terminate/2]).

init({_,http},Req,Module) ->
    {Path,_} = cowboy_http_req:binding(path,Req),
    {Method,_} = cowboy_http_req:method(Req),
    {ok,Req,#state{path=Path,method=Method,module=Module}}.

handle(Req,#state{path= <<"add_site">>,method='GET'} = State) ->
    #oauth_client{client_id=ClientID,
		  client_secret=ClientSecret} = oauth:new_client(),
    Json = mochijson2_fork:encode({struct,[{<<"client_id">>,ClientID},
					   {<<"client_secret">>,ClientSecret}]}),
    {ok,Req2} = cowboy_http_req:reply(200,[],[Json],Req),
    {ok,Req2,State};

handle(Req,#state{path= <<"authorize">>,method=Method,module=Module} = State) ->
    AuthReq = get_auth_req(Req), 
    Result = case oauth:valid_authorize_req(AuthReq) of
		 {ok,#auth_req{scope=Scope} = AuthReq2} ->
		     case Method of
			 'GET' ->
			     show_login_page(Scope,Module,Req);
			 'POST' ->
			     valid_login(AuthReq2, State, Module, Req)
		     end;
		 {error,Error} ->
		     {error,Error}
	     end,

    % Handle Errors
    case Result of
	{ok,NewReq} ->
	    {ok,NewReq,State};
	{error,#auth_error{error=invalid_redirect_uri} = AuthError} ->
	    {ok,Req} = Module:show_error_page(AuthError,Req),
	    {ok,Req,State};
	{error,AuthError} ->
	    ErrURI = oauth:format_authrize_error_uri(AuthReq,AuthError,fun cowboy_http:urlencode/1),
	    {ok,Req} = redirect(ErrURI,Req),
	    {ok,Req,State}
    end;       

handle(Req,#state{path= <<"token">>,method='POST'} = State) ->

    % @TODO Make this code reusable %
    ClientAuthData = get_client_auth_data(Req),
    % ----------------------------- %
    
    Result = case oauth:valid_client_authorization(ClientAuthData) of
		 {ok,Client_ID} ->
		     TokenReq = get_token_req(Req),
		     case oauth:token(TokenReq,Client_ID) of
			 {ok,Token} ->
			     {ok,Req2} = cowboy_http_req:reply(200,[{'Content-Type',<<"application/json">>},
								    {'Cache-Control',<<"no-store">>},
								    {'Pragma',<<"no-store">>}],
							       oauth:format_token_resp_json(Token),Req),
			     {ok,Req2};
			 {error,_} = Error -> Error
		     end;
		 {error,unauth} ->
		     {error,#token_error{error= unauthorized_client,
					 error_description= <<"Client authorization failed">>}}
	     end,
    case Result of
	{ok,NewReq} ->
	    {ok,NewReq,State};
	{error,TokenError} ->
	    ErrorJSON = oauth:format_token_error_json(TokenError),
	    {ok,NewReq} = cowboy_http_req:reply(400,[{'Content-Type',<<"application/json">>},
						     {'Cache-Control',<<"no-store">>},
						     {'Pragma',<<"no-store">>} ],ErrorJSON,Req),
	    {ok,NewReq,State}
    end.
    
terminate(Req,State) ->
    ok.

%% ===================================================================
%%% Internal Helpers
%% ===================================================================

show_login_page(Scope,Module,Req) ->
    {Path,_} = cowboy_http_req:raw_path(Req),
    {QS,_} = cowboy_http_req:raw_qs(Req),
    URI = <<Path/binary,"?",QS/binary>>,
    {ok,Req2} = Module:show_login_page(URI,Scope,Req),
    {ok,Req2}.

valid_login(AuthReq2, State, Module, Req) ->
    case Module:valid_login(Req) of
	{valid,Grant,NewScope,Req2} ->
	    URI = case oauth:authorize(AuthReq2#auth_req{scope=NewScope},Grant) of
		      {ok,#auth_resp{} = AuthResp} -> 
			  oauth:format_authrize_resp_uri(AuthReq2,
							 AuthResp,
							 fun cowboy_http:urlencode/1);
		      {ok, #token_resp{} = TokenResp} ->
			  oauth:format_token_resp_uri(AuthReq2,
						      TokenResp,
						      fun cowboy_http:urlencode/1)
		  end,
	    ?DBG("Redirect: ~p",[URI]),
	    {ok,Req3} = redirect(URI,Req2),
	    {ok,Req3};		  
	{invalid,_} ->
	    {error,#auth_error{error=access_denied,
			       error_description= <<"The resource owner or authorization server denied the request">>,
			       state=State
			      }};
	{noreply,Req2} ->
	    {ok,Req2}
    end.

get_auth_req(Req) ->
    {Response_type,_} = cowboy_http_req:qs_val(<<"response_type">>, Req),
    {Client_id,_}     = cowboy_http_req:qs_val(<<"client_id">>, Req),
    {Redirect_uri,_}  = cowboy_http_req:qs_val(<<"redirect_uri">>, Req),
    {Scope,_}         = cowboy_http_req:qs_val(<<"scope">>, Req),
    {State,_}         = cowboy_http_req:qs_val(<<"state">>, Req),
    #auth_req{response_type=Response_type,
	      client_id=Client_id,
	      redirect_uri=Redirect_uri,
	      scope=Scope,
	      state=State}.

get_token_req(Req) ->
    {PostVars,_} = cowboy_http_req:body_qs(Req),
    Grant_type = proplists:get_value(<<"grant_type">>,PostVars),
    Code = proplists:get_value(<<"code">>,PostVars),
    Scope = proplists:get_value(<<"scope">>,PostVars),
    RefreshToken = proplists:get_value(<<"refresh_token">>,PostVars),
    Redirect_uri = proplists:get_value(<<"redirect_uri">>,PostVars),
    #token_req{grant_type=Grant_type,
	       code=Code,

	       refresh_token=RefreshToken,
	       scope=Scope,

	       redirect_uri=Redirect_uri}.

get_client_auth_data(Req) ->
    {PostVars,_} = cowboy_http_req:body_qs(Req),
    Client_id = proplists:get_value(<<"client_id">>,PostVars),
    Client_secret = proplists:get_value(<<"client_secret">>,PostVars),
    #oauth_client{client_id=Client_id,
		  client_secret=Client_secret}.
					 

redirect(URI,Req) ->
    {ok,Req2} = cowboy_http_req:reply(302, [{<<"Location">>, URI}], <<"">>, Req),
    {ok,Req2}.

