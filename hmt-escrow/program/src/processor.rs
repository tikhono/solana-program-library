//! Program state processor

use crate::error::EscrowError;
use crate::instruction::EscrowInstruction;
use crate::state::*;
use num_traits::FromPrimitive;
use solana_program::clock::UnixTimestamp;
use solana_program::program::invoke_signed;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    decode_error::DecodeError,
    entrypoint::ProgramResult,
    info,
    program_error::{PrintProgramError, ProgramError},
    program_option::COption,
    program_pack::{IsInitialized, Pack},
    pubkey::Pubkey,
    sysvar::Sysvar,
};
use spl_token::state::Account as TokenAccount;

/// Program state handler.
pub struct Processor {}

impl Processor {
    /// Calculates the authority id by generating a program address.
    pub fn authority_id(
        escrow_program_id: &Pubkey,
        escrow_account_key: &Pubkey,
        bump_seed: u8,
    ) -> Result<Pubkey, ProgramError> {
        Pubkey::create_program_address(
            &[&escrow_account_key.to_bytes()[..32], &[bump_seed]],
            escrow_program_id,
        )
        .or(Err(ProgramError::IncorrectProgramId))
    }

    /// Generates seed bump for escrow authority
    pub fn find_authority_bump_seed(
        escrow_program_id: &Pubkey,
        escrow_account_key: &Pubkey,
    ) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[&escrow_account_key.to_bytes()[..32]], escrow_program_id)
    }

    /// Verifies if transaction is signed by the trusted handler
    fn check_trusted_handler(escrow: &Escrow, trusted_handler_info: &AccountInfo) -> ProgramResult {
        // Check if instruction is signed by the trusted handler
        if !trusted_handler_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Check is signer is either launcher or canceler authority
        if *trusted_handler_info.key == escrow.launcher {
            return Ok(());
        }
        if *trusted_handler_info.key == escrow.canceler {
            return Ok(());
        }

        // Check for reputation and recording oracles
        if let COption::Some(pubkey) = escrow.reputation_oracle {
            if *trusted_handler_info.key == pubkey {
                return Ok(());
            }
        }
        if let COption::Some(pubkey) = escrow.recording_oracle {
            if *trusted_handler_info.key == pubkey {
                return Ok(());
            }
        }

        // Trusted handler not recognized
        Err(EscrowError::UnauthorizedSigner.into())
    }

    fn get_escrow_with_state_check(
        escrow_info: &AccountInfo,
        clock: &Clock,
        trusted_handler_info: &AccountInfo,
        allowed_states: Vec<EscrowState>,
    ) -> Result<Escrow, ProgramError> {
        let escrow = Escrow::unpack_unchecked(&escrow_info.data.borrow())?;

        // Check if escrow account exists and is initialized
        if !escrow.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        // Check escrow account expiration
        if escrow.expires < clock.unix_timestamp {
            return Err(EscrowError::EscrowExpired.into());
        }

        // Check escrow state
        if !allowed_states.contains(&escrow.state) {
            return Err(EscrowError::WrongState.into());
        }

        Self::check_trusted_handler(&escrow, trusted_handler_info)?;

        Ok(escrow)
    }

    /// Issue a spl_token `Transfer` instruction.
    #[allow(clippy::too_many_arguments)]
    pub fn token_transfer<'a>(
        escrow_account_key: &Pubkey,
        token_program: AccountInfo<'a>,
        source: AccountInfo<'a>,
        destination: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        bump_seed: u8,
        amount: u64,
    ) -> ProgramResult {
        let authority_signature_seeds = [&escrow_account_key.to_bytes()[..32], &[bump_seed]];
        let signers = &[&authority_signature_seeds[..]];

        let ix = spl_token::instruction::transfer(
            token_program.key,
            source.key,
            destination.key,
            authority.key,
            &[],
            amount,
        )?;

        invoke_signed(
            &ix,
            &[source, destination, authority, token_program],
            signers,
        )
    }

    /// Processes `Initialize` instruction.
    pub fn process_initialize(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        duration: u64,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let clock = &Clock::from_account_info(next_account_info(account_info_iter)?)?;

        let token_mint_info = next_account_info(account_info_iter)?;
        let token_account_info = next_account_info(account_info_iter)?;
        let launcher_info = next_account_info(account_info_iter)?;
        let canceler_info = next_account_info(account_info_iter)?;
        let canceler_token_account_info = next_account_info(account_info_iter)?;

        let escrow = Box::new(Escrow::unpack_unchecked(&escrow_info.data.borrow())?);

        // Only new unitialized accounts are supported
        if escrow.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Check duration validity
        if duration == 0 {
            return Err(EscrowError::EscrowExpired.into());
        }

        // Calculate authority key and bump seed
        let (authority_key, bump_seed) =
            Self::find_authority_bump_seed(program_id, escrow_info.key);

        // Token account should be owned by the contract authority
        let token_account = Box::new(TokenAccount::unpack_unchecked(
            &token_account_info.data.borrow(),
        )?);
        if token_account.owner != authority_key {
            return Err(EscrowError::TokenAccountAuthority.into());
        }

        // Check token account mints
        if token_account.mint != *token_mint_info.key {
            return Err(EscrowError::WrongTokenMint.into());
        }
        let canceler_token_account = Box::new(TokenAccount::unpack_unchecked(
            &canceler_token_account_info.data.borrow(),
        )?);
        if canceler_token_account.mint != *token_mint_info.key {
            return Err(EscrowError::WrongTokenMint.into());
        }

        let escrow = Box::new(Escrow {
            state: EscrowState::Launched,
            expires: clock.unix_timestamp + duration as i64,
            bump_seed,
            token_mint: *token_mint_info.key,
            token_account: *token_account_info.key,
            launcher: *launcher_info.key,
            canceler: *canceler_info.key,
            canceler_token_account: *canceler_token_account_info.key,
            total_amount: 100,
            total_recipients: 1,
            ..Default::default()
        });

        Escrow::pack(*escrow, &mut escrow_info.data.borrow_mut())?;
        Ok(())
    }

    /// Processes `Setup` instruction.
    pub fn process_setup(
        accounts: &[AccountInfo],
        reputation_oracle_stake: u8,
        recording_oracle_stake: u8,
        manifest_url: &DataUrl,
        manifest_hash: &DataHash,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let trusted_handler_info = next_account_info(account_info_iter)?;
        let clock = &Clock::from_account_info(next_account_info(account_info_iter)?)?;

        let reputation_oracle_info = next_account_info(account_info_iter)?;
        let reputation_oracle_token_account_info = next_account_info(account_info_iter)?;
        let recording_oracle_info = next_account_info(account_info_iter)?;
        let recording_oracle_token_account_info = next_account_info(account_info_iter)?;

        let mut escrow = Self::get_escrow_with_state_check(
            escrow_info,
            clock,
            trusted_handler_info,
            vec![EscrowState::Launched],
        )?;

        // Check stake value validity
        let total_stake: u8 = reputation_oracle_stake
            .checked_add(recording_oracle_stake)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if total_stake == 0 || total_stake > 100 {
            return Err(EscrowError::StakeOutOfBounds.into());
        }

        // Check token account mints
        let reputation_oracle_token_account =
            TokenAccount::unpack_unchecked(&reputation_oracle_token_account_info.data.borrow())?;
        if reputation_oracle_token_account.mint != escrow.token_mint {
            return Err(EscrowError::WrongTokenMint.into());
        }
        let recording_oracle_token_account =
            TokenAccount::unpack_unchecked(&recording_oracle_token_account_info.data.borrow())?;
        if recording_oracle_token_account.mint != escrow.token_mint {
            return Err(EscrowError::WrongTokenMint.into());
        }

        // Update escrow fields with the new values
        escrow.reputation_oracle = COption::Some(*reputation_oracle_info.key);
        escrow.reputation_oracle_token_account =
            COption::Some(*reputation_oracle_token_account_info.key);
        escrow.reputation_oracle_stake = reputation_oracle_stake;

        escrow.recording_oracle = COption::Some(*recording_oracle_info.key);
        escrow.recording_oracle_token_account =
            COption::Some(*recording_oracle_token_account_info.key);
        escrow.recording_oracle_stake = recording_oracle_stake;

        escrow.manifest_url = *manifest_url;
        escrow.manifest_hash = *manifest_hash;

        escrow.state = EscrowState::Pending;

        Escrow::pack(escrow, &mut escrow_info.data.borrow_mut())?;
        Ok(())
    }

    /// Processes `StoreResults` instruction.
    pub fn process_store_results(
        accounts: &[AccountInfo],
        total_amount: u64,
        total_recipients: u64,
        final_results_url: &DataUrl,
        final_results_hash: &DataHash,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let trusted_handler_info = next_account_info(account_info_iter)?;
        let clock = &Clock::from_account_info(next_account_info(account_info_iter)?)?;

        let mut escrow = Self::get_escrow_with_state_check(
            escrow_info,
            clock,
            trusted_handler_info,
            vec![EscrowState::Pending, EscrowState::Partial],
        )?;

        // Save final amounts and results
        escrow.total_amount = total_amount;
        escrow.total_recipients = total_recipients;
        escrow.final_results_url = *final_results_url;
        escrow.final_results_hash = *final_results_hash;

        Escrow::pack(escrow, &mut escrow_info.data.borrow_mut())?;

        Ok(())
    }

    /// Processes `Payout` instruction.
    pub fn process_payout(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        amount: u64,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let trusted_handler_info = next_account_info(account_info_iter)?;
        let clock = &Clock::from_account_info(next_account_info(account_info_iter)?)?;
        let token_account_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let recipient_token_account_info = next_account_info(account_info_iter)?;
        let reputation_oracle_token_account_info = next_account_info(account_info_iter)?;
        let recording_oracle_token_account_info = next_account_info(account_info_iter)?;
        let token_program_info = next_account_info(account_info_iter)?;

        let mut escrow = Self::get_escrow_with_state_check(
            escrow_info,
            clock,
            trusted_handler_info,
            vec![EscrowState::Pending, EscrowState::Partial],
        )?;

        // Check all accounts validity
        if *token_account_info.key != escrow.token_account
            || *reputation_oracle_token_account_info.key
                != escrow
                    .reputation_oracle_token_account
                    .ok_or(EscrowError::OracleNotInitialized)?
            || *recording_oracle_token_account_info.key
                != escrow
                    .recording_oracle_token_account
                    .ok_or(EscrowError::OracleNotInitialized)?
            || *authority_info.key
                != Self::authority_id(program_id, escrow_info.key, escrow.bump_seed)?
        {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Check account balance
        let token_account = TokenAccount::unpack_unchecked(&token_account_info.data.borrow())?;
        if token_account.amount < amount {
            return Err(EscrowError::NotEnoughBalance.into());
        }

        // Check if not too many payouts
        if (escrow.sent_amount + amount > escrow.total_amount)
            || (escrow.sent_recipients + 1 > escrow.total_recipients)
        {
            return Err(EscrowError::TooManyPayouts.into());
        }

        // Calculate fees
        let reputation_oracle_fee_amount = amount
            .checked_mul(escrow.reputation_oracle_stake as u64)
            .unwrap_or(0)
            .checked_div(100)
            .unwrap_or(0);
        let recording_oracle_fee_amount = amount
            .checked_mul(escrow.recording_oracle_stake as u64)
            .unwrap_or(0)
            .checked_div(100)
            .unwrap_or(0);
        let recipient_amount = amount
            .saturating_sub(reputation_oracle_fee_amount)
            .saturating_sub(recording_oracle_fee_amount);

        // Send tokens
        if recipient_amount != 0 {
            Self::token_transfer(
                escrow_info.key,
                token_program_info.clone(),
                token_account_info.clone(),
                recipient_token_account_info.clone(),
                authority_info.clone(),
                escrow.bump_seed,
                recipient_amount,
            )?;
        }
        if reputation_oracle_fee_amount != 0 {
            Self::token_transfer(
                escrow_info.key,
                token_program_info.clone(),
                token_account_info.clone(),
                reputation_oracle_token_account_info.clone(),
                authority_info.clone(),
                escrow.bump_seed,
                reputation_oracle_fee_amount,
            )?;
        }
        if recording_oracle_fee_amount != 0 {
            Self::token_transfer(
                escrow_info.key,
                token_program_info.clone(),
                token_account_info.clone(),
                recording_oracle_token_account_info.clone(),
                authority_info.clone(),
                escrow.bump_seed,
                recording_oracle_fee_amount,
            )?;
        }

        escrow.sent_amount += amount;
        escrow.sent_recipients += 1;

        if escrow.sent_recipients == escrow.total_recipients
            && escrow.sent_amount == escrow.total_amount
        {
            escrow.state = EscrowState::Paid;
        } else {
            escrow.state = EscrowState::Partial;
        }

        Escrow::pack(escrow, &mut escrow_info.data.borrow_mut())?;

        Ok(())
    }

    /// Processes `Cancel` instruction.
    pub fn process_cancel(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let trusted_handler_info = next_account_info(account_info_iter)?;
        let token_account_info = next_account_info(account_info_iter)?;
        let authority_info = next_account_info(account_info_iter)?;
        let canceler_token_account_info = next_account_info(account_info_iter)?;
        let token_program_info = next_account_info(account_info_iter)?;

        let mut escrow = Escrow::unpack_unchecked(&escrow_info.data.borrow())?;

        // Check if escrow account exists and is initialized
        if !escrow.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        // Check escrow state
        if escrow.state == EscrowState::Complete || escrow.state == EscrowState::Paid {
            return Err(EscrowError::WrongState.into());
        }

        Self::check_trusted_handler(&escrow, trusted_handler_info)?;

        // Check all accounts validity
        if *token_account_info.key != escrow.token_account
            || *canceler_token_account_info.key != escrow.canceler_token_account
            || *authority_info.key
                != Self::authority_id(program_id, escrow_info.key, escrow.bump_seed)?
        {
            return Err(ProgramError::InvalidInstructionData);
        }

        // Check account balance
        let token_account = TokenAccount::unpack_unchecked(&token_account_info.data.borrow())?;
        if token_account.amount == 0 {
            return Err(EscrowError::NotEnoughBalance.into());
        }

        // Call token contract to do transfer
        Self::token_transfer(
            escrow_info.key,
            token_program_info.clone(),
            token_account_info.clone(),
            canceler_token_account_info.clone(),
            authority_info.clone(),
            escrow.bump_seed,
            token_account.amount,
        )?;

        escrow.state = EscrowState::Cancelled;

        Escrow::pack(escrow, &mut escrow_info.data.borrow_mut())?;

        Ok(())
    }

    /// Processes `Complete` instruction.
    pub fn process_complete(accounts: &[AccountInfo]) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let escrow_info = next_account_info(account_info_iter)?;
        let trusted_handler_info = next_account_info(account_info_iter)?;
        let clock = &Clock::from_account_info(next_account_info(account_info_iter)?)?;

        let mut escrow = Self::get_escrow_with_state_check(
            escrow_info,
            clock,
            trusted_handler_info,
            vec![EscrowState::Paid],
        )?;

        escrow.state = EscrowState::Complete;

        Escrow::pack(escrow, &mut escrow_info.data.borrow_mut())?;

        Ok(())
    }

    /// Processes all Escrow instructions
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], input: &[u8]) -> ProgramResult {
        let instruction = EscrowInstruction::unpack(input)?;

        match instruction {
            EscrowInstruction::Initialize { duration } => {
                info!("Instruction: Initialize");
                Self::process_initialize(program_id, accounts, duration)
            }
            EscrowInstruction::Setup {
                reputation_oracle_stake,
                recording_oracle_stake,
                manifest_url,
                manifest_hash,
            } => {
                info!("Instruction: Setup");
                Self::process_setup(
                    accounts,
                    reputation_oracle_stake,
                    recording_oracle_stake,
                    &manifest_url,
                    &manifest_hash,
                )
            }
            EscrowInstruction::StoreResults {
                total_amount,
                total_recipients,
                final_results_url,
                final_results_hash,
            } => {
                info!("Instruction: Store Results");
                Self::process_store_results(
                    accounts,
                    total_amount,
                    total_recipients,
                    &final_results_url,
                    &final_results_hash,
                )
            }
            EscrowInstruction::Payout { amount } => {
                info!("Instruction: Payout");
                Self::process_payout(program_id, accounts, amount)
            }
            EscrowInstruction::Cancel => {
                info!("Instruction: Payout");
                Self::process_cancel(program_id, accounts)
            }
            EscrowInstruction::Complete => {
                info!("Instruction: Payout");
                Self::process_complete(accounts)
            }
        }
    }
}

impl PrintProgramError for EscrowError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        match self {
            EscrowError::UnauthorizedSigner => info!("Error: unauthorized signer"),
            EscrowError::EscrowExpired => info!("Error: escrow expired"),
            EscrowError::StakeOutOfBounds => info!("Error: stake out of bounds"),
            EscrowError::TokenAccountAuthority => info!("Error: token account authority"),
            EscrowError::WrongTokenMint => info!("Error: wrong token mint"),
            EscrowError::WrongState => info!("Error: wrong escrow state"),
            EscrowError::NotEnoughBalance => info!("Error: not enough balance"),
            EscrowError::OracleNotInitialized => info!("Error: oracle not initialized"),
            EscrowError::TooManyPayouts => info!("Error: too many payouts"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::*;
    use solana_program::{
        instruction::Instruction, program_pack::Pack, program_stubs, rent::Rent, sysvar,
    };
    use solana_sdk::account::{create_account, create_is_signer_account_infos, Account};
    use spl_token::{
        instruction::{initialize_account, initialize_mint},
        processor::Processor as TokenProcessor,
        state::{Account as SplAccount, Mint as SplMint},
    };

    /// Test program id for the token program.
    const TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([1u8; 32]);

    /// Test program id for the token program.
    const ESCROW_PROGRAM_ID: Pubkey = Pubkey::new_from_array([2u8; 32]);

    /// Actual stake account program id, used for tests
    fn escrow_program_id() -> Pubkey {
        "rK6j1hcHDTWerdrAS2w3BFifjHkPrRrnGYC7GRNwqKF"
            .parse::<Pubkey>()
            .unwrap()
    }
    struct TestSyscallStubs {}
    impl program_stubs::SyscallStubs for TestSyscallStubs {
        fn sol_invoke_signed(
            &self,
            instruction: &Instruction,
            account_infos: &[AccountInfo],
            signers_seeds: &[&[&[u8]]],
        ) -> ProgramResult {
            info!("TestSyscallStubs::sol_invoke_signed()");

            let mut new_account_infos = vec![];
            for meta in instruction.accounts.iter() {
                for account_info in account_infos.iter() {
                    if meta.pubkey == *account_info.key {
                        let mut new_account_info = account_info.clone();
                        for seeds in signers_seeds.iter() {
                            let signer =
                                Pubkey::create_program_address(seeds, &ESCROW_PROGRAM_ID).unwrap();
                            if *account_info.key == signer {
                                new_account_info.is_signer = true;
                            }
                        }
                        new_account_infos.push(new_account_info);
                    }
                }
            }

            match instruction.program_id {
                TOKEN_PROGRAM_ID => invoke_token(&new_account_infos, &instruction.data),
                pubkey => {
                    if pubkey == escrow_program_id() {
                        invoke_stake(&new_account_infos, &instruction.data)
                    } else {
                        Err(ProgramError::IncorrectProgramId)
                    }
                }
            }
        }
    }

    /// Mocks token instruction invocation
    pub fn invoke_token<'a>(account_infos: &[AccountInfo<'a>], input: &[u8]) -> ProgramResult {
        spl_token::processor::Processor::process(&TOKEN_PROGRAM_ID, &account_infos, &input)
    }

    /// Mocks stake account instruction invocation
    pub fn invoke_stake<'a>(_account_infos: &[AccountInfo<'a>], _input: &[u8]) -> ProgramResult {
        // For now always return ok
        Ok(())
    }
    fn test_syscall_stubs() {
        use std::sync::Once;
        static ONCE: Once = Once::new();

        ONCE.call_once(|| {
            program_stubs::set_syscall_stubs(Box::new(TestSyscallStubs {}));
        });
    }

    fn account_minimum_balance() -> u64 {
        Rent::default().minimum_balance(SplAccount::get_packed_len())
    }

    fn mint_minimum_balance() -> u64 {
        Rent::default().minimum_balance(SplMint::get_packed_len())
    }

    struct TokenInfo {
        key: Pubkey,
        account: Account,
        owner: Pubkey,
    }

    fn create_token_account(
        program_id: &Pubkey,
        mint_key: &Pubkey,
        mint_account: &mut Account,
        owner: &Pubkey,
        owner_account: &mut Account,
        lamports: u64,
    ) -> TokenInfo {
        let mut token = TokenInfo {
            key: Pubkey::new_unique(),
            account: Account::new(
                account_minimum_balance() + lamports,
                SplAccount::get_packed_len(),
                &program_id,
            ),
            owner: *owner,
        };
        let mut rent_sysvar_account = create_account(&Rent::free(), 1);

        // create account
        do_process_instruction(
            initialize_account(&program_id, &token.key, &mint_key, &token.owner).unwrap(),
            vec![
                &mut token.account,
                mint_account,
                owner_account,
                &mut rent_sysvar_account,
            ],
        )
        .unwrap();

        token
    }

    fn create_mint(
        program_id: &Pubkey,
        authority_key: &Pubkey,
        lamports: u64,
    ) -> (Pubkey, Account) {
        let mint_key = Pubkey::new_unique();
        let mut mint_account = Account::new(
            mint_minimum_balance() + lamports,
            SplMint::get_packed_len(),
            &program_id,
        );
        let mut rent_sysvar_account = create_account(&Rent::free(), 1);

        // create token mint
        do_process_instruction(
            initialize_mint(&program_id, &mint_key, authority_key, None, 2).unwrap(),
            vec![&mut mint_account, &mut rent_sysvar_account],
        )
        .unwrap();

        (mint_key, mint_account)
    }

    fn do_process_instruction(
        instruction: Instruction,
        accounts: Vec<&mut Account>,
    ) -> ProgramResult {
        test_syscall_stubs();

        // approximate the logic in the actual runtime which runs the instruction
        // and only updates accounts if the instruction is successful
        let mut account_clones = accounts.iter().map(|x| (*x).clone()).collect::<Vec<_>>();
        let mut meta = instruction
            .accounts
            .iter()
            .zip(account_clones.iter_mut())
            .map(|(account_meta, account)| (&account_meta.pubkey, account_meta.is_signer, account))
            .collect::<Vec<_>>();
        let mut account_infos = create_is_signer_account_infos(&mut meta);
        let res = if instruction.program_id == ESCROW_PROGRAM_ID {
            Processor::process(&instruction.program_id, &account_infos, &instruction.data)
        } else {
            TokenProcessor::process(&instruction.program_id, &account_infos, &instruction.data)
        };

        if res.is_ok() {
            let mut account_metas = instruction
                .accounts
                .iter()
                .zip(accounts)
                .map(|(account_meta, account)| (&account_meta.pubkey, account))
                .collect::<Vec<_>>();
            for account_info in account_infos.iter_mut() {
                for account_meta in account_metas.iter_mut() {
                    if account_info.key == account_meta.0 {
                        let account = &mut account_meta.1;
                        account.owner = *account_info.owner;
                        account.lamports = **account_info.lamports.borrow();
                        account.data = account_info.data.borrow().to_vec();
                    }
                }
            }
        }
        res
    }

    /// Escrow data
    #[repr(C)]
    #[derive(Clone, Debug, PartialEq)]
    pub struct EscrowInfo {
        ///Escrow pubkey
        pub escrow_key: Pubkey,
        ///Account
        pub escrow_account: Account,
        /// Current state of escrow entity: Uninitialized, Launched, Pending, Partial, Paid, Complete, Cancelled
        pub state: EscrowState,
        /// Escrow expiration timestamp
        pub expires: UnixTimestamp,
        /// Program authority
        pub authority: Pubkey,
        /// Program authority account
        pub authority_account: Account,
        /// Program authority bump seed
        pub bump_seed: u8,
        /// Mint for the token handled by the escrow
        pub token_mint: Pubkey,
        /// Account to hold tokens for sendout, its owner should be escrow contract authority
        pub token_account: Pubkey,
        /// Account to hold tokens for sendout, its owner should be escrow contract authority
        pub token_account_account: Account,
        /// Pubkey of the reputation oracle
        pub reputation_oracle: COption<Pubkey>,
        /// Account for the reputation oracle to receive fee
        pub reputation_oracle_token_account: COption<Pubkey>,
        /// Account for the reputation oracle to receive fee
        pub reputation_oracle_token_account_account: Account,
        /// Reputation oracle fee (in percents)
        pub reputation_oracle_stake: u8,
        /// Pubkey of the recording oracle
        pub recording_oracle: COption<Pubkey>,
        /// Account for the recording oracle to receive fee
        pub recording_oracle_token_account: COption<Pubkey>,
        /// Account for the recording oracle to receive fee
        pub recording_oracle_token_account_account: Account,
        /// Recording oracle fee (in percents)
        pub recording_oracle_stake: u8,
        /// Launcher pubkey
        pub launcher: Pubkey,
        /// Launcher Account
        pub launcher_account: Account,
        /// Canceler pubkey
        pub canceler: Pubkey,
        /// Account for the canceler to receive back tokens
        pub canceler_token_account: Pubkey,
        /// Account for the canceler to receive back tokens
        pub canceler_token_account_account: Account,
        /// Total amount of tokens to pay out
        pub total_amount: u64,
        /// Total number of recipients
        pub total_recipients: u64,
        /// Amount in tokens already sent
        pub sent_amount: u64,
        /// Number of recipients already sent to
        pub sent_recipients: u64,
        /// Job manifest url
        pub manifest_url: DataUrl,
        /// Job manifest hash
        pub manifest_hash: DataHash,
        /// Job results url
        pub final_results_url: DataUrl,
        /// Job results hash
        pub final_results_hash: DataHash,
        /// Recipient key
        pub recipient: Pubkey,
        /// Recipient account
        pub recipient_account: Account,
    }

    fn initialize_escrow() -> EscrowInfo {
        let escrow = Pubkey::new_unique();
        let mut escrow_account = Account::new(1000, Escrow::LEN, &ESCROW_PROGRAM_ID);

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let (authority, bump_seed) =
            Processor::find_authority_bump_seed(&ESCROW_PROGRAM_ID, &escrow);

        let mut authority_account = Account::new(0, 0, &authority);

        let (token_mint, mut token_mint_account) = create_mint(&TOKEN_PROGRAM_ID, &authority, 1000);

        let mut token = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let launcher = Pubkey::new_unique();
        let mut launcher_account = Account::new(0, 0, &launcher);

        let canceler = Pubkey::new_unique();
        let mut canceler_account = Account::default();

        let mut canceler_token = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let _result = do_process_instruction(
            initialize(
                &ESCROW_PROGRAM_ID,
                &escrow,
                &token_mint,
                &token.key,
                &launcher,
                &canceler,
                &canceler_token.key,
                1606402240,
            )
            .unwrap(),
            vec![
                &mut escrow_account,
                &mut clock, //sysvar
                &mut token_mint_account,
                &mut token.account,
                &mut launcher_account,
                &mut canceler_account,
                &mut canceler_token.account,
            ],
        )
        .expect("Error on escrow initialize");
        EscrowInfo {
            escrow_key: escrow,
            escrow_account,
            expires: 1606402240,
            authority,
            authority_account,
            bump_seed,
            state: EscrowState::Launched,
            token_mint,
            token_account: token.key,
            token_account_account: token.account,
            reputation_oracle: COption::Some(Pubkey::new_from_array([3; 32])),
            reputation_oracle_token_account: COption::Some(Pubkey::new_from_array([4; 32])),
            reputation_oracle_token_account_account: Account::default(),
            reputation_oracle_stake: 5,
            recording_oracle: COption::None,
            recording_oracle_token_account: COption::Some(Pubkey::new_from_array([6; 32])),
            recording_oracle_token_account_account: Account::default(),
            recording_oracle_stake: 10,
            launcher,
            launcher_account,
            canceler,
            canceler_token_account: canceler_token.key,
            canceler_token_account_account: canceler_token.account,
            total_amount: 20000000,
            total_recipients: 1000000,
            sent_amount: 2000000,
            sent_recipients: 100000,
            manifest_url: DataUrl::default(),
            manifest_hash: DataHash::default(),
            final_results_url: DataUrl::default(),
            final_results_hash: DataHash::default(),
            recipient: Default::default(),
            recipient_account: Default::default(),
        }
    }

    fn initialize_and_setup_escrow() -> EscrowInfo {
        let escrow = Pubkey::new_unique();
        let mut escrow_account = Account::new(1000, Escrow::LEN, &ESCROW_PROGRAM_ID);

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let (authority, bump_seed) =
            Pubkey::find_program_address(&[&escrow.to_bytes()[..32]], &ESCROW_PROGRAM_ID);
        let mut authority_account = Account::new(1000, 0, &authority);

        let (token_mint, mut token_mint_account) = create_mint(&TOKEN_PROGRAM_ID, &authority, 1000);
        let mut token = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let launcher = Pubkey::new_unique();
        let mut launcher_account = Account::new(1000, 0, &launcher);

        let canceler = Pubkey::new_unique();

        let mut canceler_token = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let _result = do_process_instruction(
            spl_token::instruction::mint_to(
                &TOKEN_PROGRAM_ID,
                &token_mint,
                &token.key,
                &authority,
                &[],
                100,
            )
            .unwrap(),
            vec![
                &mut token_mint_account,
                &mut token.account, //sysvar
                &mut authority_account,
            ],
        )
        .expect("Error on token minting");

        let _result = do_process_instruction(
            initialize(
                &ESCROW_PROGRAM_ID,
                &escrow,
                &token_mint,
                &token.key,
                &launcher,
                &canceler,
                &canceler_token.key,
                1606402240,
            )
            .unwrap(),
            vec![
                &mut escrow_account,
                &mut clock, //sysvar
                &mut token_mint_account,
                &mut token.account,
                &mut Account::default(),
                &mut Account::default(),
                &mut canceler_token.account,
            ],
        )
        .expect("Error on escrow initialize");

        let recipient = Pubkey::new_unique();
        let recipient_token_account = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let reputation_oracle = Pubkey::new_unique();
        let mut reputation_oracle_account = Account::new(1000, 0, &reputation_oracle);

        let mut reputation_oracle_token_account = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let recording_oracle = Pubkey::new_unique();
        let mut recording_oracle_account = Account::new(1000, 0, &recording_oracle);

        let mut recording_oracle_token_account = create_token_account(
            &TOKEN_PROGRAM_ID,
            &token_mint,
            &mut token_mint_account,
            &authority,
            &mut authority_account,
            1000,
        );

        let reputation_oracle_stake = 30;
        let recording_oracle_stake = 40;

        let _result = do_process_instruction(
            setup(
                &ESCROW_PROGRAM_ID,
                &escrow,
                &launcher,
                &reputation_oracle,
                &reputation_oracle_token_account.key,
                reputation_oracle_stake,
                &recording_oracle,
                &recording_oracle_token_account.key,
                recording_oracle_stake,
                &DataUrl::default(),
                &DataHash::default(),
            )
            .unwrap(),
            vec![
                &mut escrow_account,
                &mut launcher_account,
                &mut clock, //sysvar
                &mut reputation_oracle_account,
                &mut reputation_oracle_token_account.account,
                &mut recording_oracle_account,
                &mut recording_oracle_token_account.account,
            ],
        )
        .expect("Error on escrow setup");

        EscrowInfo {
            escrow_key: escrow,
            escrow_account,
            expires: 1606402240,
            authority,
            authority_account,
            bump_seed,
            state: EscrowState::Launched,
            token_mint,
            token_account: token.key,
            token_account_account: token.account,
            reputation_oracle: COption::Some(reputation_oracle),
            reputation_oracle_token_account: COption::from(reputation_oracle_token_account.key),
            reputation_oracle_token_account_account: reputation_oracle_token_account.account,
            reputation_oracle_stake,
            recording_oracle: COption::Some(recording_oracle),
            recording_oracle_token_account: COption::from(recording_oracle_token_account.key),
            recording_oracle_token_account_account: recording_oracle_token_account.account,
            recording_oracle_stake,
            launcher,
            launcher_account,
            canceler,
            canceler_token_account: canceler_token.key,
            canceler_token_account_account: canceler_token.account,
            total_amount: 20000000,
            total_recipients: 1000000,
            sent_amount: 2000000,
            sent_recipients: 100000,
            manifest_url: DataUrl::default(),
            manifest_hash: DataHash::default(),
            final_results_url: DataUrl::default(),
            final_results_hash: DataHash::default(),
            recipient,
            recipient_account: recipient_token_account.account,
        }
    }

    #[test]
    fn test_initialize() {
        let escrow_info = initialize_escrow();
        // Read account data

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();
        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Launched => {
                assert_eq!(escrow.expires, escrow_info.expires);
                assert_eq!(escrow.bump_seed, escrow_info.bump_seed);
                assert_eq!(escrow.token_mint, escrow_info.token_mint);
                assert_eq!(escrow.token_account, escrow_info.token_account);
                assert_eq!(escrow.launcher, escrow_info.launcher);
                assert_eq!(escrow.canceler, escrow_info.canceler);
                assert_eq!(
                    escrow.canceler_token_account,
                    escrow_info.canceler_token_account
                );
            }
            _ => panic!("Escrow in a wrong state"),
        }
    }

    #[test]
    fn test_setup() {
        let escrow_info = initialize_and_setup_escrow();
        // Read account data

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();
        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Pending => {
                assert_eq!(escrow.reputation_oracle, escrow_info.reputation_oracle);
                assert_eq!(
                    escrow.reputation_oracle_token_account,
                    escrow_info.reputation_oracle_token_account
                );
                assert_eq!(
                    escrow.reputation_oracle_stake,
                    escrow_info.reputation_oracle_stake
                );
                assert_eq!(escrow.recording_oracle, escrow_info.recording_oracle);
                assert_eq!(
                    escrow.recording_oracle_token_account,
                    escrow_info.recording_oracle_token_account
                );
                assert_eq!(
                    escrow.recording_oracle_stake,
                    escrow_info.recording_oracle_stake
                );
                assert_eq!(escrow.manifest_url, escrow_info.manifest_url);
                assert_eq!(escrow.manifest_hash, escrow_info.manifest_hash);
            }
            _ => panic!("Escrow in a wrong state"),
        }
    }

    #[test]
    fn test_store_results() {
        let mut escrow_info = initialize_and_setup_escrow();

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let _result = do_process_instruction(
            store_results(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
                100,
                1,
                &DataUrl::default(),
                &DataHash::default(),
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut clock, //sysvar
            ],
        )
        .expect("Error on escrow store result");

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();

        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Pending | EscrowState::Partial => {
                assert_eq!(escrow.total_amount, 100);
                assert_eq!(escrow.total_recipients, 1);
                assert_eq!(escrow.final_results_url, DataUrl::default());
                assert_eq!(escrow.final_results_hash, DataHash::default());
            }
            _ => panic!("Escrow in a wrong state"),
        }
    }

    #[test]
    fn test_payout() {
        let mut escrow_info = initialize_and_setup_escrow();

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let _result = do_process_instruction(
            payout(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
                &escrow_info.token_account,
                &escrow_info.authority,
                &escrow_info.recipient,
                &escrow_info.reputation_oracle_token_account.unwrap(),
                &escrow_info.recording_oracle_token_account.unwrap(),
                &TOKEN_PROGRAM_ID,
                10,
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut clock, //sysvar
                &mut escrow_info.token_account_account,
                &mut escrow_info.authority_account,
                &mut escrow_info.recipient_account,
                &mut escrow_info.reputation_oracle_token_account_account,
                &mut escrow_info.recording_oracle_token_account_account,
                &mut Account::default(),
            ],
        )
        .expect("Error on escrow store result");

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();

        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Pending | EscrowState::Partial => {
                assert_eq!(escrow.sent_amount, 10);
                assert_eq!(escrow.sent_recipients, 1);
            }
            _ => panic!("Escrow in a wrong state"),
        }
    }

    #[test]
    fn test_cancel() {
        let mut escrow_info = initialize_and_setup_escrow();

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let _result = do_process_instruction(
            payout(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
                &escrow_info.token_account,
                &escrow_info.authority,
                &escrow_info.recipient,
                &escrow_info.reputation_oracle_token_account.unwrap(),
                &escrow_info.recording_oracle_token_account.unwrap(),
                &TOKEN_PROGRAM_ID,
                10,
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut clock, //sysvar
                &mut escrow_info.token_account_account,
                &mut escrow_info.authority_account,
                &mut escrow_info.recipient_account,
                &mut escrow_info.reputation_oracle_token_account_account,
                &mut escrow_info.recording_oracle_token_account_account,
                &mut Account::default(),
            ],
        )
        .expect("Error on escrow payout");

        let _result = do_process_instruction(
            cancel(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
                &escrow_info.token_account,
                &escrow_info.authority,
                &escrow_info.canceler_token_account,
                &TOKEN_PROGRAM_ID,
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut escrow_info.token_account_account,
                &mut escrow_info.authority_account,
                &mut escrow_info.canceler_token_account_account,
                &mut Account::default(),
            ],
        )
        .expect("Error on escrow cancel");

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();

        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Cancelled => {}
            _ => panic!("Escrow in a wrong state"),
        }
    }

    #[test]
    fn test_complete() {
        let mut escrow_info = initialize_and_setup_escrow();

        let mut clock = Account::new(0, 100, &sysvar::clock::id());

        let _result = do_process_instruction(
            payout(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
                &escrow_info.token_account,
                &escrow_info.authority,
                &escrow_info.recipient,
                &escrow_info.reputation_oracle_token_account.unwrap(),
                &escrow_info.recording_oracle_token_account.unwrap(),
                &TOKEN_PROGRAM_ID,
                100,
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut clock, //sysvar
                &mut escrow_info.token_account_account,
                &mut escrow_info.authority_account,
                &mut escrow_info.recipient_account,
                &mut escrow_info.reputation_oracle_token_account_account,
                &mut escrow_info.recording_oracle_token_account_account,
                &mut Account::default(),
            ],
        )
        .expect("Error on escrow payout");

        let _result = do_process_instruction(
            complete(
                &ESCROW_PROGRAM_ID,
                &escrow_info.escrow_key,
                &escrow_info.launcher,
            )
            .unwrap(),
            vec![
                &mut escrow_info.escrow_account,
                &mut escrow_info.launcher_account,
                &mut clock, //sysvar
            ],
        )
        .expect("Error on escrow complete");

        let escrow = Escrow::unpack(&escrow_info.escrow_account.data).unwrap();

        match escrow.state {
            EscrowState::Uninitialized => panic!("Escrow is not initialized after init"),
            EscrowState::Complete => {}
            _ => panic!("Escrow in a wrong state"),
        }
    }
}
