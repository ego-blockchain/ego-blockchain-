-module(sbft_validator_manager).
-behaviour(gen_server).

-include("../include/sbft.hrl").

-export([start_link/0, register_validator/2, update_stake/2,
         slash_validator/2, get_validator/1, get_all_validators/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(VALIDATORS_TABLE, validators_table).

-record(validator_manager_state, {
    total_stake = 0 :: non_neg_integer(),
    slashing_events = [] :: [map()]
}).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

register_validator(ValidatorId, ValidatorData) ->
    gen_server:call(?SERVER, {register_validator, ValidatorId, ValidatorData}).

update_stake(ValidatorId, NewStake) ->
    gen_server:call(?SERVER, {update_stake, ValidatorId, NewStake}).

slash_validator(ValidatorId, Reason) ->
    gen_server:call(?SERVER, {slash_validator, ValidatorId, Reason}).

get_validator(ValidatorId) ->
    gen_server:call(?SERVER, {get_validator, ValidatorId}).

get_all_validators() ->
    gen_server:call(?SERVER, get_all_validators).

init([]) ->
    ets:new(?VALIDATORS_TABLE, [named_table, set, protected,
                               {keypos, #sbft_validator_record.id}]),
    {ok, #validator_manager_state{}}.

handle_call({register_validator, ValidatorId, ValidatorData}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [] ->
            Validator = #sbft_validator_record{
                id = ValidatorId,
                public_key = maps:get(public_key, ValidatorData),
                stake = maps:get(stake, ValidatorData, 0),
                is_active = maps:get(is_active, ValidatorData, true),
                shard_id = maps:get(shard_id, ValidatorData),
                last_seen = erlang:system_time(millisecond)
            },
            ets:insert(?VALIDATORS_TABLE, Validator),
            NewTotalStake = State#validator_manager_state.total_stake + Validator#sbft_validator_record.stake,
            NewState = State#validator_manager_state{total_stake = NewTotalStake},
            {reply, ok, NewState};
        [_] ->
            {reply, {error, already_exists}, State}
    end;

handle_call({update_stake, ValidatorId, NewStake}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [Validator] ->
            OldStake = Validator#sbft_validator_record.stake,
            UpdatedValidator = Validator#sbft_validator_record{stake = NewStake},
            ets:insert(?VALIDATORS_TABLE, UpdatedValidator),
            StakeDiff = NewStake - OldStake,
            NewTotalStake = State#validator_manager_state.total_stake + StakeDiff,
            NewState = State#validator_manager_state{total_stake = NewTotalStake},
            {reply, ok, NewState};
        [] ->
            {reply, {error, not_found}, State}
    end;

handle_call({slash_validator, ValidatorId, Reason}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [Validator] ->
            SlashedValidator = Validator#sbft_validator_record{is_active = false},
            ets:insert(?VALIDATORS_TABLE, SlashedValidator),

            SlashingEvent = #{
                validator_id => ValidatorId,
                reason => Reason,
                timestamp => erlang:system_time(millisecond),
                stake_slashed => Validator#sbft_validator_record.stake
            },
            NewSlashingEvents = [SlashingEvent | State#validator_manager_state.slashing_events],

            NewTotalStake = State#validator_manager_state.total_stake - Validator#sbft_validator_record.stake,

            NewState = State#validator_manager_state{
                total_stake = NewTotalStake,
                slashing_events = NewSlashingEvents
            },
            {reply, ok, NewState};
        [] ->
            {reply, {error, not_found}, State}
    end;

handle_call({get_validator, ValidatorId}, _From, State) ->
    case ets:lookup(?VALIDATORS_TABLE, ValidatorId) of
        [Validator] ->
            {reply, {ok, Validator}, State};
        [] ->
            {reply, {error, not_found}, State}
    end;

handle_call(get_all_validators, _From, State) ->
    Validators = ets:tab2list(?VALIDATORS_TABLE),
    {reply, {ok, Validators}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ets:delete(?VALIDATORS_TABLE),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
