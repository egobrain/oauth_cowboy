-module(oauth_to_functions).

-export([parse_transform/2, pretty_print/1]).

-record(state,{rds=[],gen=[],fns=[]}).
-record(field,{name,allowed = []}).
-record(rd,{name,fields = [] ::list(#field{})}).

% TODO: сообщения об ошибках в декораторе
parse_transform(Ast,_Options)->
    % io:format("~p~n=======~n",[Ast]),
    % io:format("~s~n=======~n",[pretty_print(Ast)]),
    {ExtendedAst2, #state{fns=Fns,rds=Rds}} = lists:mapfoldl(fun transform_node/2, #state{}, Ast),
    Ast2 = lists:flatten(lists:filter(fun(Node)-> Node =/= nil end, ExtendedAst2)),
    Ast3 = add_export(Ast2,[{to_proplist,1}]),
    %io:format("~p~n<<<<~n",[Ast3]),
    %io:format("~s~n>>>>~n",[pretty_print(Ast3)]),

    % io:format("~n~n~n~n~p~n>>>>~n",[Rds]),
    % io:format("~n~n~n~n~p~n",[State#state.rds]),
    Ast3.



pretty_print(Ast) -> lists:flatten([erl_pp:form(N) || N<-Ast]).

% emit_errors_for_rogue_decorators(DecoratorList)->
%     [{error,{Line,erl_parse,["rogue decorator ", io_lib:format("~p",[D]) ]}} || {attribute, Line, decorate, D} <- DecoratorList].

transform_node(Node={attribute,_Line,type,{{record,Name},Props,_}},#state{rds=Rds} = State) ->
    {Node,State#state{rds=[#rd{name=Name,fields=[parse_rt(RT) || RT <- Props]} | Rds]}};

transform_node(Node={attribute, _Line, to_functions, Record}, #state{gen=Gen} = State) ->
    case lists:foldl(fun(_,true) -> true;
    			(R,false) -> R =:= Record
    		     end,false,Gen) of
     	true ->
    	    {nil,State};
    	false ->		    
    	    {nil, State#state{gen=[Record|Gen]}}
    end;


transform_node({eof,Line},#state{gen=Gen,rds=Rds} = State) ->
    % Name = ok,
    ToProplist = {function,Line,to_proplist,1,
    		  lists:foldl(
    		    fun(Rec,Clause) ->
    			    case lists:keyfind(Rec,#rd.name,Rds) of
    				false -> Clause;
    				#rd{fields=Fields} ->
    					 [to_proplist_clause(Rec,Fields,Line)|Clause]
    			    end
    		    end,
    		    [],
    		    Gen
    		   )
    		 },
    {[ToProplist],State};
transform_node(Node, State) ->
    {Node, State}.

parse_rt({record_field,_Line,{atom,_Line,Name}}) ->
    #field{name=Name,allowed=[{atom,undefined}]};
parse_rt({record_field,_Line,{atom,_Line,Name},{Type,_Line,Default}}) ->
    #field{name=Name,allowed=[{Type,Default}]};
parse_rt({typed_record_field,Record,Types}) ->
    Field = parse_rt(Record),
    Field#field{allowed=parse_type(Types)}.

parse_type({type,_Line,Value,[]}) ->
    [{type,Value}];
parse_type({type,_Line,union,List}) ->
    lists:foldl(fun(X,Acc) -> Acc++parse_type(X) end,[],List);
parse_type({Type,_Line,Value}) ->
    [{Type,Value}];
parse_type({type,_Line,record,_}) ->
    [].

to_proplist_clause(Record,Fields,L) ->
    R = fun(Atom,Line) ->
		{tuple,Line,[{atom,Line,Atom},
			     {record_field,Line,{var,Line,'Record'},Record,{atom,Line,Atom}}
			    ]}
	end,
    {clause,L,
     [{match,L,{record,L,Record,[]},{var,L,'Record'}}],
     [],
     [cons(R,Fields,L)]
    }.

cons(_F,[],Line) ->
    {nil,Line};
cons(F,[#field{name=Field}|Else],Line) ->
    {cons,Line,F(Field,Line),cons(F,Else,Line+1)}.

add_export([],_Funs) ->
    [];
add_export([{attribute,Line,module,_ModuleName} = ModuleAttr|Rest],Funs) ->
    Exports = {attribute,Line,export,[FName || FName <- Funs]},
    [ModuleAttr,Exports|Rest];
add_export([H|Rest],Funs) ->
    [H|add_export(Rest,Funs)].

