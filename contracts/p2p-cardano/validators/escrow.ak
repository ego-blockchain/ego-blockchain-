use aiken/collection/list
use aiken/crypto.{
  Signature, VerificationKey, VerificationKeyHash, blake2b_224,
  verify_ed25519_signature,
}
use aiken/interval.{Finite, Interval}
use aiken/primitive/bytearray
use cardano/address.{Address, Credential, Script}
use cardano/assets.{lovelace_of}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}

pub type EscrowDatum {
  trade_id: ByteArray,
  seller: Address,
  buyer: Address,
  arbiter: VerificationKeyHash,
  fee_receiver: Address,
  total: Int,
  fee: Int,
  fallback_at: Int,
  frozen: Bool,
}

pub type Action {
  Release
  Cancel
  CancelFor { vkey: VerificationKey, signature: Signature }
  Resolve { to_buyer: Bool }
  Freeze
  FreezeFor { vkey: VerificationKey, signature: Signature }
  Reclaim
}

pub const auth_domain: ByteArray = "ego-escrow/cardano/v1"

pub const min_fee_output: Int = 1_000_000

pub const action_cancel: Int = 2

pub const action_freeze: Int = 5

pub fn auth_message(script: ByteArray, trade_id: ByteArray, action: Int) -> ByteArray {
  auth_domain
    |> bytearray.concat(script)
    |> bytearray.concat(trade_id)
    |> bytearray.concat(bytearray.push(#"", action))
}

fn key_hash(address: Address) -> VerificationKeyHash {
  expect address.VerificationKey(h) = address.payment_credential
  h
}

fn signed_by(tx: Transaction, who: VerificationKeyHash) -> Bool {
  list.has(tx.extra_signatories, who)
}

fn authorized(
  vkey: VerificationKey,
  signature: Signature,
  who: Address,
  message: ByteArray,
) -> Bool {
  and {
    blake2b_224(vkey) == key_hash(who),
    verify_ed25519_signature(vkey, message, signature),
  }
}

fn paid_to(outputs: List<Output>, to: Address) -> Int {
  list.foldl(
    outputs,
    0,
    fn(o, sum) {
      if o.address == to {
        sum + lovelace_of(o.value)
      } else {
        sum
      }
    },
  )
}

fn pays_buyer(outputs: List<Output>, d: EscrowDatum) -> Bool {
  if d.buyer == d.fee_receiver {
    paid_to(outputs, d.buyer) >= d.total
  } else {
    and {
      paid_to(outputs, d.buyer) >= d.total - d.fee,
      or {
        d.fee < min_fee_output,
        paid_to(outputs, d.fee_receiver) >= d.fee,
      },
    }
  }
}

fn refunds_seller(outputs: List<Output>, d: EscrowDatum) -> Bool {
  paid_to(outputs, d.seller) >= d.total
}

fn stays_frozen(outputs: List<Output>, own: Input, d: EscrowDatum) -> Bool {
  let frozen: Data = EscrowDatum { ..d, frozen: True }
  and {
    !d.frozen,
    list.any(
      outputs,
      fn(o) {
        and {
          o.address == own.output.address,
          lovelace_of(o.value) >= lovelace_of(own.output.value),
          o.datum == InlineDatum(frozen),
          o.reference_script == None,
        }
      },
    ),
  }
}

fn starts_at_or_after(range: Interval, at: Int) -> Bool {
  when range.lower_bound.bound_type is {
    Finite(start) -> start >= at
    _ -> False
  }
}

fn only_input_from(inputs: List<Input>, credential: Credential) -> Bool {
  list.count(inputs, fn(i) { i.output.address.payment_credential == credential }) == 1
}

validator escrow {
  spend(
    datum: Option<EscrowDatum>,
    action: Action,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum
    expect Some(own) = transaction.find_input(tx.inputs, own_ref)
    let own_credential = own.output.address.payment_credential
    expect Script(own_hash) = own_credential
    and {
      only_input_from(tx.inputs, own_credential),
      lovelace_of(own.output.value) >= d.total,
      when action is {
        Release ->
          and {
            signed_by(tx, key_hash(d.seller)),
            pays_buyer(tx.outputs, d),
          }
        Cancel ->
          and {
            signed_by(tx, key_hash(d.buyer)),
            refunds_seller(tx.outputs, d),
          }
        CancelFor { vkey, signature } ->
          and {
            authorized(
              vkey,
              signature,
              d.buyer,
              auth_message(own_hash, d.trade_id, action_cancel),
            ),
            refunds_seller(tx.outputs, d),
          }
        Resolve { to_buyer } ->
          and {
            signed_by(tx, d.arbiter),
            if to_buyer {
              pays_buyer(tx.outputs, d)
            } else {
              refunds_seller(tx.outputs, d)
            },
          }
        Freeze ->
          and {
            or {
              signed_by(tx, key_hash(d.buyer)),
              signed_by(tx, d.arbiter),
            },
            stays_frozen(tx.outputs, own, d),
          }
        FreezeFor { vkey, signature } ->
          and {
            authorized(
              vkey,
              signature,
              d.buyer,
              auth_message(own_hash, d.trade_id, action_freeze),
            ),
            stays_frozen(tx.outputs, own, d),
          }
        Reclaim ->
          and {
            signed_by(tx, key_hash(d.seller)),
            !d.frozen,
            starts_at_or_after(tx.validity_range, d.fallback_at),
            refunds_seller(tx.outputs, d),
          }
      },
    }
  }

  else(_) {
    fail
  }
}

const test_script: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const test_trade: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const seller_pkh: ByteArray =
  #"01010101010101010101010101010101010101010101010101010101"

const buyer_vkey: ByteArray =
  #"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"

const buyer_pkh: ByteArray =
  #"008b47844d92812fc30d1f0ac9b6fbf38778ccba9db8312ad9079079"

const arbiter_pkh: ByteArray =
  #"03030303030303030303030303030303030303030303030303030303"

const fee_pkh: ByteArray =
  #"04040404040404040404040404040404040404040404040404040404"

const stranger_vkey: ByteArray =
  #"6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1"

const stranger_pkh: ByteArray =
  #"fd5939fb5601e5b41eee666dba14c0a7d151d4cd9b0e16691ce3a9a4"

const buyer_cancel_sig: ByteArray =
  #"18113fa96978187fd31385401f806ff9d745421410ab3fadc77cf05041d4237b99a84b0f10e16b5f8e65b5f1572246b32fa6873be8e18366649f9f532f49db02"

const buyer_freeze_sig: ByteArray =
  #"bd841c00f7a4b8823405a2fe19801314e8d97948181ecfc1a1872f9ca6a241a8f36a520a45902a0d4a47340e0d2d4fa172f0416f8893e44c4fc90bec581af306"

const stranger_cancel_sig: ByteArray =
  #"f7e1297fa2013209215cea4af74bfb6f77f08f1f1792784f3826fd042ce72a6ef0c0bab9aecdc7988c2048e30d3f1a29c7c49cc98d3a998316ffa8d42566f703"

const buyer_sig_other_trade: ByteArray =
  #"9dc8482e97cb8e6a63ca109a255c951a90ed982b3d40200d39c4017c4d9eb0a7a8afdbbefd1dfd67436dbee1a211b8b6048b30a46a15aa793bbae1615099150d"

const buyer_sig_other_script: ByteArray =
  #"8b603617bdd9ea5452e6b5873b53e01da04dab71239e50967d3b5f335a5d797939883b21ea69d8fcffcc415d72586e726205c093d3b3b5cf32125917224dfa0a"

const own_ref: OutputReference =
  OutputReference {
    transaction_id: #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    output_index: 0,
  }

fn wallet(pkh: ByteArray) -> Address {
  address.from_verification_key(pkh)
}

fn sample() -> EscrowDatum {
  EscrowDatum {
    trade_id: test_trade,
    seller: wallet(seller_pkh),
    buyer: wallet(buyer_pkh),
    arbiter: arbiter_pkh,
    fee_receiver: wallet(fee_pkh),
    total: 101_000_000,
    fee: 1_000_000,
    fallback_at: 5_000_000,
    frozen: False,
  }
}

fn escrow_input(d: EscrowDatum, lovelace: Int) -> Input {
  Input {
    output_reference: own_ref,
    output: Output {
      address: address.from_script(test_script),
      value: assets.from_lovelace(lovelace),
      datum: InlineDatum(d),
      reference_script: None,
    },
  }
}

fn funds(pkh: ByteArray) -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      output_index: 1,
    },
    output: Output {
      address: wallet(pkh),
      value: assets.from_lovelace(20_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn pay(to: Address, lovelace: Int) -> Output {
  Output {
    address: to,
    value: assets.from_lovelace(lovelace),
    datum: NoDatum,
    reference_script: None,
  }
}

fn spending(
  d: EscrowDatum,
  signers: List<ByteArray>,
  outputs: List<Output>,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [escrow_input(d, d.total), funds(seller_pkh)],
    outputs: outputs,
    extra_signatories: signers,
  }
}

fn run(d: EscrowDatum, action: Action, tx: Transaction) -> Bool {
  escrow.spend(Some(d), action, own_ref, tx)
}

fn released(d: EscrowDatum) -> List<Output> {
  [pay(d.buyer, d.total - d.fee), pay(d.fee_receiver, d.fee)]
}

fn refunded(d: EscrowDatum) -> List<Output> {
  [pay(d.seller, d.total)]
}

fn frozen_copy(d: EscrowDatum) -> Output {
  Output {
    address: address.from_script(test_script),
    value: assets.from_lovelace(d.total),
    datum: InlineDatum(EscrowDatum { ..d, frozen: True }),
    reference_script: None,
  }
}

test the_seller_releases_to_the_buyer_and_the_fee_receiver() {
  let d = sample()
  run(d, Release, spending(d, [seller_pkh], released(d)))
}

test a_release_needs_the_sellers_signature() {
  let d = sample()
  and {
    !run(d, Release, spending(d, [buyer_pkh], released(d))),
    !run(d, Release, spending(d, [arbiter_pkh], released(d))),
    !run(d, Release, spending(d, [], released(d))),
  }
}

test a_release_must_pay_the_buyer_and_the_fee_in_full() {
  let d = sample()
  and {
    !run(
      d,
      Release,
      spending(
        d,
        [seller_pkh],
        [pay(d.buyer, d.total - d.fee - 1), pay(d.fee_receiver, d.fee)],
      ),
    ),
    !run(d, Release, spending(d, [seller_pkh], [pay(d.buyer, d.total - d.fee)])),
    !run(
      d,
      Release,
      spending(
        d,
        [seller_pkh],
        [pay(wallet(stranger_pkh), d.total - d.fee), pay(d.fee_receiver, d.fee)],
      ),
    ),
  }
}

test a_fee_below_one_ada_needs_no_output_of_its_own() {
  let d = EscrowDatum { ..sample(), total: 50_500_000, fee: 500_000 }
  run(d, Release, spending(d, [seller_pkh], [pay(d.buyer, 50_000_000)]))
}

test the_buyer_cancels_and_the_seller_is_refunded() {
  let d = sample()
  and {
    run(d, Cancel, spending(d, [buyer_pkh], refunded(d))),
    !run(d, Cancel, spending(d, [seller_pkh], refunded(d))),
    !run(d, Cancel, spending(d, [buyer_pkh], [pay(d.seller, d.total - 1)])),
  }
}

test a_relayed_cancel_carries_the_buyers_signature() {
  let d = sample()
  let relayer = spending(d, [], refunded(d))
  run(d, CancelFor { vkey: buyer_vkey, signature: buyer_cancel_sig }, relayer)
}

test a_relayed_cancel_refuses_other_signatures() {
  let d = sample()
  let relayer = spending(d, [], refunded(d))
  and {
    !run(
      d,
      CancelFor { vkey: stranger_vkey, signature: stranger_cancel_sig },
      relayer,
    ),
    !run(d, CancelFor { vkey: buyer_vkey, signature: buyer_freeze_sig }, relayer),
    !run(
      d,
      CancelFor { vkey: buyer_vkey, signature: buyer_sig_other_trade },
      relayer,
    ),
    !run(
      d,
      CancelFor { vkey: buyer_vkey, signature: buyer_sig_other_script },
      relayer,
    ),
  }
}

test a_relayed_cancel_still_refunds_the_seller_in_full() {
  let d = sample()
  !run(
    d,
    CancelFor { vkey: buyer_vkey, signature: buyer_cancel_sig },
    spending(d, [], [pay(wallet(stranger_pkh), d.total)]),
  )
}

test the_arbiter_resolves_either_way() {
  let d = sample()
  and {
    run(d, Resolve { to_buyer: True }, spending(d, [arbiter_pkh], released(d))),
    run(d, Resolve { to_buyer: False }, spending(d, [arbiter_pkh], refunded(d))),
    !run(d, Resolve { to_buyer: True }, spending(d, [arbiter_pkh], refunded(d))),
    !run(d, Resolve { to_buyer: True }, spending(d, [stranger_pkh], released(d))),
    !run(d, Resolve { to_buyer: False }, spending(d, [seller_pkh], refunded(d))),
  }
}

test the_buyer_or_the_arbiter_freezes_in_place() {
  let d = sample()
  and {
    run(d, Freeze, spending(d, [buyer_pkh], [frozen_copy(d)])),
    run(d, Freeze, spending(d, [arbiter_pkh], [frozen_copy(d)])),
    !run(d, Freeze, spending(d, [seller_pkh], [frozen_copy(d)])),
    !run(d, Freeze, spending(d, [stranger_pkh], [frozen_copy(d)])),
  }
}

test a_freeze_keeps_the_value_and_the_terms() {
  let d = sample()
  let short =
    Output { ..frozen_copy(d), value: assets.from_lovelace(d.total - 1) }
  let other_terms =
    Output {
      ..frozen_copy(d),
      datum: InlineDatum(
        EscrowDatum { ..d, frozen: True, buyer: wallet(stranger_pkh) },
      ),
    }
  let elsewhere = Output { ..frozen_copy(d), address: wallet(buyer_pkh) }
  let unfrozen = Output { ..frozen_copy(d), datum: InlineDatum(d) }
  and {
    !run(d, Freeze, spending(d, [buyer_pkh], [short])),
    !run(d, Freeze, spending(d, [buyer_pkh], [other_terms])),
    !run(d, Freeze, spending(d, [buyer_pkh], [elsewhere])),
    !run(d, Freeze, spending(d, [buyer_pkh], [unfrozen])),
  }
}

test an_escrow_freezes_only_once() {
  let d = EscrowDatum { ..sample(), frozen: True }
  !run(d, Freeze, spending(d, [arbiter_pkh], [frozen_copy(d)]))
}

test a_signed_freeze_can_be_relayed() {
  let d = sample()
  and {
    run(
      d,
      FreezeFor { vkey: buyer_vkey, signature: buyer_freeze_sig },
      spending(d, [], [frozen_copy(d)]),
    ),
    !run(
      d,
      FreezeFor { vkey: buyer_vkey, signature: buyer_cancel_sig },
      spending(d, [], [frozen_copy(d)]),
    ),
  }
}

test the_seller_reclaims_after_the_fallback() {
  let d = sample()
  let after =
    Transaction {
      ..spending(d, [seller_pkh], refunded(d)),
      validity_range: interval.after(d.fallback_at),
    }
  let before =
    Transaction {
      ..spending(d, [seller_pkh], refunded(d)),
      validity_range: interval.after(d.fallback_at - 1),
    }
  let unbounded = spending(d, [seller_pkh], refunded(d))
  and {
    run(d, Reclaim, after),
    !run(d, Reclaim, before),
    !run(d, Reclaim, unbounded),
    !run(EscrowDatum { ..d, frozen: True }, Reclaim, after),
    !run(d, Reclaim, Transaction { ..after, extra_signatories: [buyer_pkh] }),
  }
}

test two_escrows_cannot_share_one_payout() {
  let d = sample()
  let twin =
    Input {
      ..escrow_input(d, d.total),
      output_reference: OutputReference { ..own_ref, output_index: 1 },
    }
  let tx =
    Transaction {
      ..spending(d, [seller_pkh], released(d)),
      inputs: [escrow_input(d, d.total), twin, funds(seller_pkh)],
    }
  !run(d, Release, tx)
}

test an_underfunded_escrow_cannot_be_released() {
  let d = sample()
  let tx =
    Transaction {
      ..spending(d, [seller_pkh], released(d)),
      inputs: [escrow_input(d, d.total - 1), funds(seller_pkh)],
    }
  !run(d, Release, tx)
}

test a_buyer_who_is_also_the_fee_receiver_gets_everything() {
  let d = EscrowDatum { ..sample(), fee_receiver: wallet(buyer_pkh) }
  and {
    run(d, Release, spending(d, [seller_pkh], [pay(d.buyer, d.total)])),
    !run(d, Release, spending(d, [seller_pkh], [pay(d.buyer, d.total - 1)])),
  }
}

test a_script_seller_cannot_release() fail {
  let d = EscrowDatum { ..sample(), seller: address.from_script(test_script) }
  run(d, Release, spending(d, [seller_pkh], released(d)))
}
