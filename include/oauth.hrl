-record(oauth_client,{
	  client_id :: binary(),
	  client_secret :: binary()
	 }).

%% == Authorize ==

-record(auth_req,{
	  response_type     :: binary(),
	  client_id         :: binary(),
	  redirect_uri      :: binary(),
	  scope             :: binary(),
	  state             :: binary()
	 }).

-record(auth_resp,{
	  code              :: binary(),
	  state             :: binary()
	 }).

-record(auth_error,{
	  error             :: binary(),
	  error_description :: binary(),
	  error_uri         :: binary(),
	  state             :: binary() 
	 }).

%% == Token ==

-record(token_req,{
	  grant_type        :: binary(),
	  refresh_token     :: binary(),
	  code              :: binary(),
	  redirect_uri      :: binary(),

	  scope             :: binary()
	 }).

-record(token_resp,{
	  access_token      :: binary(), 
	  token_type        :: binary(), 
	  expires_in        :: binary(), 
	  refresh_token     :: binary(), 
	  scope             :: binary(),
	  state             :: binary()
	 }).

-record(token_error,{
	  error             :: binary(),
	  error_description :: binary(),
	  error_uri         :: binary()
	 }).

%% == Access ==
-define(EXPIRES_IN,3600).

-record(access_token,{
	  access_token      :: binary(),
 	  token_type        :: binary(),
	  created           :: binary(),
	  expires_in        :: non_neg_integer(),
	  refresh_token     :: binary(),
	  scope             :: binary(),
	  grant,
	  client_id
	 }).
