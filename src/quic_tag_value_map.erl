-module(quic_tag_value_map).

-compile(export_all).

parse(<<_Key:4/binary, TagCnt:32/little, TagBin:TagCnt/binary-unit:64, R/binary>>) ->
    Key = normalize_tag_key(_Key),
    {KVMap, R2} = parse_kv(TagBin, {#{}, 0, R}),
    #{tag=> Key, tags=> KVMap}
    .

parse_kv(<<>>, {Map, _, R}) -> {Map, R};
parse_kv(<<_Key:4/binary, Offset:32/little, B1/binary>>, {Map, LastOffset, R}) ->
    Key = normalize_tag_key(_Key),
    OffsetAdjusted = Offset - LastOffset,
    <<Val:OffsetAdjusted/binary, R1/binary>> = R,

    parse_kv(B1, {Map#{Key=>normalize_kv_value(Key, Val)}, Offset, R1})
    .

normalize_kv_value(<<"PAD">>, V) -> V;
normalize_kv_value(<<"SNI">>, V) -> V;
normalize_kv_value(<<"VER">>, V) -> V;
%Common Certificate sets
normalize_kv_value(<<"CCS">>, V) -> V;
%Max streams per connection
normalize_kv_value(<<"MSPC">>, <<V:32/little>>) -> V;
%Clients user agent id
normalize_kv_value(<<"UAID">>, V) -> V;
%Connetion ID truncation
normalize_kv_value(<<"TCID">>, <<V:32/little>>) -> V;
%Proof demand
normalize_kv_value(<<"PDMD">>, V) -> V;
%Socket receive buffer
normalize_kv_value(<<"SRBF">>, <<V:32/little>>) -> V;
%Idle connection state
normalize_kv_value(<<"ICSL">>, <<V:32/little>>) -> V;
%Ukn
normalize_kv_value(<<"CTIM">>, V) -> V;
%Ukn
normalize_kv_value(<<"NONP">>, V) -> V;
%Silently close on timeout
normalize_kv_value(<<"SCLS">>, <<V:32/little>>) -> V;
%Ukn
normalize_kv_value(<<"CSCT">>, V) -> V;
%Connection options
normalize_kv_value(<<"COPT">>, V) -> V;
%Inital session/connection
normalize_kv_value(<<"CFCW">>, <<V:32/little>>) -> V;
%Inital stream flow control
normalize_kv_value(<<"SFCW">>, <<V:32/little>>) -> V.




normalize_tag_key(<<Key:3/binary, 0>>) -> Key;
normalize_tag_key(<<Key/binary>>) -> Key.