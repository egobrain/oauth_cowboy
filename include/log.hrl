-import(io).
-define(DBG(A), io:format("(~w:~b) ~p ~n", [?MODULE, ?LINE | A])).
-define(DBG(F, A), io:format("(~w:~b) " ++ F ++ "~n", [?MODULE, ?LINE | A])).
-define(DBG_OTHER(A), io:format("(~w:~b) OTHER MSG!!! : ~ps ~n", [?MODULE, ?LINE , A])).

-define(E_INFO(A), error_logger:error_msg({?MODULE, ?LINE},A)).
-define(E_INFO(F,A), error_logger:error_msg({?MODULE, ?LINE},io_lib:format(F,A))).

-define(LOG_ERROR(Prefix,Format,Data), error_logger:error_msg(Prefix++"(~w,~w): "++Format++"~n~n",[?MODULE,?LINE|Data])).
 
