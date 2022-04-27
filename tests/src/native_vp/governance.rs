//! # Governance validity predicate tests
//!
//! The testing strategy is heavily relying on
//! [proptest state machine testing](https://github.com/AltSysrq/proptest/pull/257)
//! together with
//! [higher-order strategies](https://altsysrq.github.io/proptest-book/proptest/tutorial/higher-order.html).
//!
//! The system is being tested with arbitrary valid governance parameters,
//! arbitrary valid initial state and:
//!
//! 1. One or more arbitrary valid transition. The happy path, these are very
//!    simple. We just test that they get accepted.
//! 1. One or more arbitrary valid transition, modified to make at least one of
//!    them invalid. Must be rejected.
//! 1. Arbitrary invalid storage modification. Must be rejected.
//!
//! ## Parameters
//! Some valid governance parameters are generated with a strategy from
//! [`anoma::ledger::governance::parameters::testing::arb_gov_params`].
//!
//! ## Valid transitions
//!
//! The list below includes state requirements and the storage key changes
//! expected for a valid transition. Valid transitions can be composed into an
//! ordered sequence. The composed transitions must still be a valid transition,
//! provided all the state requirements are valid (a transition may depend on
//! the modifications of its predecessor transition).
//!
//! - Init proposal:
//!   - Storage key changes:
//!     - `#{gov}/counter`
//!     - `#{gov}/proposal/{id}/content`
//!     - `#{gov}/proposal/{id}/author`
//!     - `#{gov}/proposal/{id}/start_epoch`
//!     - `#{gov}/proposal/{id}/end_epoch`
//!     - `#{gov}/proposal/{id}/grace_epoch`
//!     - `#{gov}/proposal/{id}/funds`
//!     - `#{gov}/proposal/{id}/proposal_code`: optional
//!     - `#{gov}/proposal/epoch/{epoch}/{id}`
//!     - `#{native_token}/balance/#{gov}`
//!   - Requires that the proposal `id` is equal to the counter before prior to
//!     tx execution.
//!   - The `counter` value must be incremented by 1 for each proposal.
//!   - The content's bytes length must be <= `max_proposal_content_size` param.
//!   - The `author` must be an existing address.
//!   - The `start_epoch` must be > `current_epoch`
//!   - The `start_epoch` must be < `end_epoch`
//!   - `end_epoch - start_epoch % min_period == 0` (parameter)
//!   - `end_epoch - start_epoch >= min_period`
//!   - `end_epoch < grace_epoch`
//!   - `grace_epoch - end_epoch >= min_grace_epoch` (parameter)
//!   - `funds` must be equal to the balance increase of the governance's native
//!     token
//!   - `funds >= min_proposal_fund` (parameter)
//!   - If `proposal_code` is used, its bytes length must be <=
//!     `max_proposal_code_size` param.
//!   - In the `#{gov}/proposal/epoch/{epoch}/{id}` storage key, the `epoch`
//!     must be equal to `grace_epoch`
//!
//! - Vote for proposal
//!   - Storage key changes:
//!     - `#{gov}/proposal/{id}/vote/{validator}/{delegator}`: For validator
//!       vote `delegator == validator`, for delegator vote they differ.
//!   - The proposal `id` must be <= `counter` prior to tx execution to ensure
//!     that proposal exists
//!   - `voting_start_epoch <= current_epoch <= voting_end_epoch`
//!   - If `validator != delegator`, the `delegator` must have a delegation to
//!     the `validator`
//!   - If `validator == delegator`, the `validator` must be in the validator
//!     set (active or inactive) and `current_epoch <= 2/3 * start_epoch +
//!     end_epoch`
