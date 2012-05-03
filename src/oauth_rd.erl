%%%-------------------------------------------------------------------
%%% @author egobrain <>
%%% @copyright (C) 2012, egobrain
%%% @doc
%%%
%%% @end
%%% Created : 27 Apr 2012 by egobrain <>
%%%-------------------------------------------------------------------
-module(oauth_rd).
-include("oauth.hrl").

-compile([{parse_transform,oauth_to_functions}]).

-to_functions(token_resp).
-to_functions(token_error).


