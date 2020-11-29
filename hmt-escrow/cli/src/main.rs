use hmt_escrow::state::DataHash;
use hmt_escrow::state::DataUrl;
use chrono::prelude::*;
use clap::{
    crate_description, crate_name, crate_version, value_t, value_t_or_exit, App, AppSettings, Arg,
    SubCommand,
};
use hex;
use hmt_escrow::{
    self, instruction::initialize as initialize_escrow, processor::Processor as EscrowProcessor,
    state::Escrow, instruction::setup as setup_escrow
};
use solana_clap_utils::{
    input_parsers::{pubkey_of, value_of},
    input_validators::{is_keypair, is_parsable, is_pubkey, is_url},
    keypair::signer_from_path,
};
use solana_client::rpc_client::RpcClient;
use solana_program::{
    instruction::Instruction, program_option::COption, program_pack::Pack, pubkey::Pubkey,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::*,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_token::{self, instruction::initialize_account, state::Account as TokenAccount};
use std::{fmt::Display, process::exit, str, str::FromStr};

struct Config {
    rpc_client: RpcClient,
    verbose: bool,
    owner: Box<dyn Signer>,
    fee_payer: Box<dyn Signer>,
    commitment_config: CommitmentConfig,
}

type Error = Box<dyn std::error::Error>;
type CommandResult = Result<Option<Transaction>, Error>;

macro_rules! unique_signers {
    ($vec:ident) => {
        $vec.sort_by_key(|l| l.pubkey());
        $vec.dedup();
    };
}

fn check_fee_payer_balance(config: &Config, required_balance: u64) -> Result<(), Error> {
    let balance = config.rpc_client.get_balance(&config.fee_payer.pubkey())?;
    if balance < required_balance {
        Err(format!(
            "Fee payer, {}, has insufficient balance: {} required, {} available",
            config.fee_payer.pubkey(),
            lamports_to_sol(required_balance),
            lamports_to_sol(balance)
        )
        .into())
    } else {
        Ok(())
    }
}

fn command_create(
    config: &Config,
    mint: &Pubkey,
    launcher: &Option<Pubkey>,
    canceler: &Option<Pubkey>,
    canceler_token: &Option<Pubkey>,
    duration: u64,
) -> CommandResult {
    let escrow_token_account = Keypair::new();
    println!(
        "Creating escrow token account {}",
        escrow_token_account.pubkey()
    );

    let escrow_account = Keypair::new();

    let token_account_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(TokenAccount::LEN)?;
    let escrow_account_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(Escrow::LEN)?;
    let mut total_rent_free_balances = token_account_balance + escrow_account_balance;

    // Calculate withdraw authority used for minting pool tokens
    let (authority, _) =
        EscrowProcessor::find_authority_bump_seed(&hmt_escrow::id(), &escrow_account.pubkey());

    if config.verbose {
        println!("Escrow authority {}", authority);
    }

    let mut instructions: Vec<Instruction> = vec![
        // Account for the escrow tokens
        system_instruction::create_account(
            &config.fee_payer.pubkey(),
            &escrow_token_account.pubkey(),
            token_account_balance,
            TokenAccount::LEN as u64,
            &spl_token::id(),
        ),
        // Account for the escrow
        system_instruction::create_account(
            &config.fee_payer.pubkey(),
            &escrow_account.pubkey(),
            escrow_account_balance,
            Escrow::LEN as u64,
            &hmt_escrow::id(),
        ),
        // Initialize escrow token account
        initialize_account(
            &spl_token::id(),
            &escrow_token_account.pubkey(),
            mint,
            &authority,
        )?,
    ];

    let mut signers = vec![
        config.fee_payer.as_ref(),
        &escrow_token_account,
        &escrow_account,
    ];

    // Unwrap optionals
    let launcher: Pubkey = launcher.unwrap_or(config.owner.pubkey());
    let canceler: Pubkey = canceler.unwrap_or(config.owner.pubkey());

    let canceler_token_account = Keypair::new();
    let canceler_token: Pubkey = match canceler_token {
        Some(value) => *value,
        None => {
            println!(
                "Creating canceler token account {}",
                canceler_token_account.pubkey()
            );

            instructions.extend(vec![
                // Account for the canceler tokens
                system_instruction::create_account(
                    &config.fee_payer.pubkey(),
                    &canceler_token_account.pubkey(),
                    token_account_balance,
                    TokenAccount::LEN as u64,
                    &spl_token::id(),
                ),
                // Initialize canceler token account
                initialize_account(
                    &spl_token::id(),
                    &canceler_token_account.pubkey(),
                    mint,
                    &canceler,
                )?,
            ]);

            signers.push(&canceler_token_account);

            total_rent_free_balances += token_account_balance;

            canceler_token_account.pubkey()
        }
    };

    println!("Creating escrow {}", escrow_account.pubkey());
    instructions.extend(vec![
        // Initialize escrow account
        initialize_escrow(
            &hmt_escrow::id(),
            &escrow_account.pubkey(),
            mint,
            &escrow_token_account.pubkey(),
            &launcher,
            &canceler,
            &canceler_token,
            duration,
        )?,
    ]);

    let mut transaction =
        Transaction::new_with_payer(&instructions, Some(&config.fee_payer.pubkey()));

    let (recent_blockhash, fee_calculator) = config.rpc_client.get_recent_blockhash()?;
    check_fee_payer_balance(
        config,
        total_rent_free_balances + fee_calculator.calculate_fee(&transaction.message()),
    )?;
    unique_signers!(signers);
    transaction.sign(&signers, recent_blockhash);
    Ok(Some(transaction))
}

fn format_coption_key<'a>(optional: &'a COption<Pubkey>) -> Box<dyn std::fmt::Display + 'a> {
    match optional {
        COption::Some(key) => Box::new(key),
        COption::None => Box::new("None"),
    }
}

fn command_info(config: &Config, escrow: &Pubkey) -> CommandResult {
    let account_data = config.rpc_client.get_account_data(escrow)?;
    let escrow: Escrow = Escrow::unpack_from_slice(account_data.as_slice())?;

    println!("Escrow information");
    println!("==================");
    println!("State: {:?}", escrow.state);
    println!(
        "Expires: {}",
        NaiveDateTime::from_timestamp(escrow.expires, 0)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    );
    println!("Token mint: {}", escrow.token_mint);
    println!("Token account: {}", escrow.token_account);
    println!("Launcher: {}", escrow.launcher);
    println!("Canceler: {}", escrow.canceler);
    println!("Canceler token account: {}", escrow.canceler_token_account);
    println!("");
    println!("Reputation oracle");
    println!("=================");
    println!("Account: {}", format_coption_key(&escrow.reputation_oracle));
    println!(
        "Token account: {}",
        format_coption_key(&escrow.reputation_oracle_token_account)
    );
    println!("Fee: {}%", escrow.reputation_oracle_stake);
    println!("");
    println!("Recording oracle");
    println!("================");
    println!("Account: {}", format_coption_key(&escrow.recording_oracle));
    println!(
        "Token account: {}",
        format_coption_key(&escrow.recording_oracle_token_account)
    );
    println!("Fee: {}%", escrow.recording_oracle_stake);
    println!("");
    println!("Data");
    println!("====");
    println!(
        "Job manifest URL: {}",
        str::from_utf8(escrow.manifest_url.as_ref()).unwrap_or("")
    );
    println!(
        "Job manifest hash: {}",
        hex::encode(escrow.manifest_hash.as_ref())
    );
    println!(
        "Final results URL: {}",
        str::from_utf8(escrow.final_results_url.as_ref()).unwrap_or("")
    );
    println!(
        "Final results hash: {}",
        hex::encode(escrow.final_results_hash.as_ref())
    );
    println!("");
    println!("Amounts and recipients");
    println!("======================");
    println!(
        "Amount: {} SOL ({} SOL sent)",
        lamports_to_sol(escrow.total_amount),
        lamports_to_sol(escrow.sent_amount)
    );
    println!(
        "Recipients: {} ({} sent)",
        lamports_to_sol(escrow.total_recipients),
        lamports_to_sol(escrow.sent_recipients)
    );

    Ok(None)
}

/// Issues setup command
fn command_setup(
    config: &Config,
    escrow: &Pubkey,
    reputation_oracle: &Option<Pubkey>,
    reputation_oracle_token: &Option<Pubkey>,
    reputation_oracle_stake: u8,
    recording_oracle: &Option<Pubkey>,
    recording_oracle_token: &Option<Pubkey>,
    recording_oracle_stake: u8,
    manifest_url: &String,
    manifest_hash: &Option<String>,
) -> CommandResult {
    // Validate parameters
    if reputation_oracle_stake > 100
        || recording_oracle_stake > 100
        || reputation_oracle_stake.saturating_add(recording_oracle_stake) > 100
    {
        return Err("Invalid stake values".into());
    }

    let manifest_url: DataUrl = DataUrl::from_str(manifest_url.as_ref()).or(Err("URL too long"))?;
    let manifest_hash: DataHash = match manifest_hash {
        None => Default::default(),
        Some(value) => {
            let bytes = hex::decode(value).or(Err("Hash decoding error"))?;
            DataHash::new_from_slice(&bytes).or(Err("Wrong hash size"))?
        }
    };

    let mut instructions: Vec<Instruction> = vec![];
    let token_account_balance = config
        .rpc_client
        .get_minimum_balance_for_rent_exemption(TokenAccount::LEN)?;
    let mut total_rent_free_balances = 0;

    let mut signers = vec![
        config.fee_payer.as_ref(),
        config.owner.as_ref(),
    ];

    // Read escrow state
    let account_data = config.rpc_client.get_account_data(escrow)?;
    let escrow_info: Escrow = Escrow::unpack_from_slice(account_data.as_slice())?;

    // Unwrap optionals
    let reputation_oracle: Pubkey = reputation_oracle.unwrap_or(config.owner.pubkey());
    let recording_oracle: Pubkey = recording_oracle.unwrap_or(config.owner.pubkey());
    let reputation_oracle_token_account = Keypair::new();
    let reputation_oracle_token: Pubkey = match reputation_oracle_token {
        Some(value) => *value,
        None => {
            println!(
                "Creating reputation oracle token account {}",
                reputation_oracle_token_account.pubkey()
            );

            instructions.extend(vec![
                // Account for the reputation oracle tokens
                system_instruction::create_account(
                    &config.fee_payer.pubkey(),
                    &reputation_oracle_token_account.pubkey(),
                    token_account_balance,
                    TokenAccount::LEN as u64,
                    &spl_token::id(),
                ),
                // Initialize reputation oracle token account
                initialize_account(
                    &spl_token::id(),
                    &reputation_oracle_token_account.pubkey(),
                    &escrow_info.token_mint,
                    &reputation_oracle,
                )?,
            ]);

            signers.push(&reputation_oracle_token_account);

            total_rent_free_balances += token_account_balance;

            reputation_oracle_token_account.pubkey()
        }
    };
    let recording_oracle_token_account = Keypair::new();
    let recording_oracle_token: Pubkey = match recording_oracle_token {
        Some(value) => *value,
        None => {
            println!(
                "Creating recording oracle token account {}",
                recording_oracle_token_account.pubkey()
            );

            instructions.extend(vec![
                // Account for the reputation oracle tokens
                system_instruction::create_account(
                    &config.fee_payer.pubkey(),
                    &recording_oracle_token_account.pubkey(),
                    token_account_balance,
                    TokenAccount::LEN as u64,
                    &spl_token::id(),
                ),
                // Initialize reputation oracle token account
                initialize_account(
                    &spl_token::id(),
                    &recording_oracle_token_account.pubkey(),
                    &escrow_info.token_mint,
                    &recording_oracle,
                )?,
            ]);

            signers.push(&recording_oracle_token_account);

            total_rent_free_balances += token_account_balance;

            recording_oracle_token_account.pubkey()
        }
    };

    instructions.extend(vec![
        // Add escrow setup instruction
        setup_escrow(
            &hmt_escrow::id(),
            &escrow,
            &config.owner.pubkey(),
            &reputation_oracle,
            &reputation_oracle_token,
            reputation_oracle_stake,
            &recording_oracle,
            &recording_oracle_token,
            recording_oracle_stake,
            &manifest_url,
            &manifest_hash,
        )?,
    ]);

    let mut transaction =
        Transaction::new_with_payer(&instructions, Some(&config.fee_payer.pubkey()));

    let (recent_blockhash, fee_calculator) = config.rpc_client.get_recent_blockhash()?;
    check_fee_payer_balance(
        config,
        total_rent_free_balances + fee_calculator.calculate_fee(&transaction.message()),
    )?;
    unique_signers!(signers);
    transaction.sign(&signers, recent_blockhash);
    Ok(Some(transaction))
}

/// Return an error if a hex cannot be parsed.
pub fn is_hex<T>(string: T) -> Result<(), String>
where
    T: AsRef<str> + Display,
{
    match hex::decode(string.as_ref()) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("{}", err)),
    }
}

fn main() {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(&config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .takes_value(false)
                .global(true)
                .help("Show additional information"),
        )
        .arg(
            Arg::with_name("json_rpc_url")
                .long("url")
                .value_name("URL")
                .takes_value(true)
                .validator(is_url)
                .help("JSON RPC URL for the cluster.  Default from the configuration file."),
        )
        .arg(
            Arg::with_name("owner")
                .long("owner")
                .value_name("KEYPAIR")
                .validator(is_keypair)
                .takes_value(true)
                .help(
                    "Specify the stake pool or stake account owner. \
                     This may be a keypair file, the ASK keyword. \
                     Defaults to the client keypair.",
                ),
        )
        .arg(
            Arg::with_name("fee_payer")
                .long("fee-payer")
                .value_name("KEYPAIR")
                .validator(is_keypair)
                .takes_value(true)
                .help(
                    "Specify the fee-payer account. \
                     This may be a keypair file, the ASK keyword. \
                     Defaults to the client keypair.",
                ),
        )
        .subcommand(SubCommand::with_name("create").about("Create a new escrow")
            .arg(
                Arg::with_name("mint")
                    .long("mint")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Mint address for the token managed by this escrow"),
            )
            .arg(
                Arg::with_name("launcher")
                    .long("launcher")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Account which can manage the escrow [default: --owner]"),
            )
            .arg(
                Arg::with_name("canceler")
                    .long("canceler")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Account which is able to cancel this escrow [default: --owner]"),
            )
            .arg(
                Arg::with_name("canceler_token")
                    .long("canceler-receiver")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Token account which can receive tokens specified by the --mint parameter [default: new token account owned by the --canceler]"),
            )
            .arg(
                Arg::with_name("duration")
                    .long("duration")
                    .short("d")
                    .validator(is_parsable::<u64>)
                    .value_name("SECONDS")
                    .takes_value(true)
                    .required(true)
                    .help("Escrow duration in seconds, once this time passes escrow contract is no longer operational"),
            )
        )
        .subcommand(SubCommand::with_name("info").about("Shows information about the escrow account")
            .arg(
                Arg::with_name("escrow")
                    .validator(is_pubkey)
                    .index(1)
                    .value_name("ESCROW_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Escrow address"),
            )
        )
        .subcommand(SubCommand::with_name("setup").about("Configures and launches escrow")
            .arg(
                Arg::with_name("escrow")
                    .validator(is_pubkey)
                    .index(1)
                    .value_name("ESCROW_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Escrow address"),
            )
            .arg(
                Arg::with_name("reputation_oracle")
                    .long("reputation-oracle")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Escrow reputation oracle address [default: --owner]"),
            )
            .arg(
                Arg::with_name("reputation_oracle_token")
                    .long("reputation-oracle-token")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Reputation oracle token address [default: new token account owned by the --reputation-oracle]"),
            )
            .arg(
                Arg::with_name("reputation_oracle_stake")
                    .long("reputation-oracle-stake")
                    .validator(is_parsable::<u8>)
                    .value_name("PERCENT")
                    .takes_value(true)
                    .required(true)
                    .help("Reputation oracle fee in payouts, from 0 to 100 percent"),
            )
            .arg(
                Arg::with_name("recording_oracle")
                    .long("recording-oracle")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Escrow recording oracle address [default: --owner]"),
            )
            .arg(
                Arg::with_name("recording_oracle_token")
                    .long("recording-oracle-token")
                    .validator(is_pubkey)
                    .value_name("ADDRESS")
                    .takes_value(true)
                    .help("Recording oracle token address [default: new token account owned by the --recording-oracle]"),
            )
            .arg(
                Arg::with_name("recording_oracle_stake")
                    .long("recording-oracle-stake")
                    .validator(is_parsable::<u8>)
                    .value_name("PERCENT")
                    .takes_value(true)
                    .required(true)
                    .help("Recording oracle fee in payouts, from 0 to 100 percent"),
            )
            .arg(
                Arg::with_name("manifest_url")
                    .long("manifest-url")
                    .validator(is_url)
                    .value_name("URL")
                    .takes_value(true)
                    .help("Job manifestr URL [default: empty string]"),
            )
            .arg(
                Arg::with_name("manifest_hash")
                    .long("manifest-hash")
                    .validator(is_hex)
                    .value_name("HEX")
                    .takes_value(true)
                    .help("20-byte SHA1 hash in hex format [default: 0-byte hash]"),
            )
        )
        .get_matches();

    let mut wallet_manager = None;
    let config = {
        let cli_config = if let Some(config_file) = matches.value_of("config_file") {
            solana_cli_config::Config::load(config_file).unwrap_or_default()
        } else {
            solana_cli_config::Config::default()
        };
        let json_rpc_url = value_t!(matches, "json_rpc_url", String)
            .unwrap_or_else(|_| cli_config.json_rpc_url.clone());

        let owner = signer_from_path(
            &matches,
            &cli_config.keypair_path,
            "owner",
            &mut wallet_manager,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });
        let fee_payer = signer_from_path(
            &matches,
            &cli_config.keypair_path,
            "fee_payer",
            &mut wallet_manager,
        )
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            exit(1);
        });
        let verbose = matches.is_present("verbose");

        Config {
            rpc_client: RpcClient::new(json_rpc_url),
            verbose,
            owner,
            fee_payer,
            commitment_config: CommitmentConfig::single(),
        }
    };

    solana_logger::setup_with_default("solana=info");

    let _ = match matches.subcommand() {
        ("create", Some(arg_matches)) => {
            let mint: Pubkey = pubkey_of(arg_matches, "mint").unwrap();
            let launcher: Option<Pubkey> = pubkey_of(arg_matches, "launcher");
            let canceler: Option<Pubkey> = pubkey_of(arg_matches, "canceler");
            let canceler_token: Option<Pubkey> = pubkey_of(arg_matches, "canceler_token");
            let duration = value_t_or_exit!(arg_matches, "duration", u64);
            command_create(
                &config,
                &mint,
                &launcher,
                &canceler,
                &canceler_token,
                duration,
            )
        }
        ("info", Some(arg_matches)) => {
            let escrow: Pubkey = pubkey_of(arg_matches, "escrow").unwrap();
            command_info(&config, &escrow)
        }
        ("setup", Some(arg_matches)) => {
            let escrow: Pubkey = pubkey_of(arg_matches, "escrow").unwrap();
            let reputation_oracle: Option<Pubkey> = pubkey_of(arg_matches, "reputation_oracle");
            let reputation_oracle_token: Option<Pubkey> =
                pubkey_of(arg_matches, "reputation_oracle_token");
            let reputation_oracle_stake =
                value_t_or_exit!(arg_matches, "reputation_oracle_stake", u8);
            let recording_oracle: Option<Pubkey> = pubkey_of(arg_matches, "recording_oracle");
            let recording_oracle_token: Option<Pubkey> =
                pubkey_of(arg_matches, "recording_oracle_token");
            let recording_oracle_stake =
                value_t_or_exit!(arg_matches, "recording_oracle_stake", u8);
            let manifest_url: String =
                value_of(arg_matches, "manifest_url").unwrap_or(String::new());
            let manifest_hash: Option<String> = value_of(arg_matches, "manifest_hash");
            command_setup(
                &config,
                &escrow,
                &reputation_oracle,
                &reputation_oracle_token,
                reputation_oracle_stake,
                &recording_oracle,
                &recording_oracle_token,
                recording_oracle_stake,
                &manifest_url,
                &manifest_hash,
            )
        }
        _ => unreachable!(),
    }
    .and_then(|transaction| {
        if let Some(transaction) = transaction {
            // TODO: Upgrade to solana-client 1.3 and
            // `send_and_confirm_transaction_with_spinner_and_commitment()` with single
            // confirmation by default for better UX
            let signature = config
                .rpc_client
                .send_and_confirm_transaction_with_spinner_and_commitment(
                    &transaction,
                    config.commitment_config,
                )?;
            println!("Signature: {}", signature);
        }
        Ok(())
    })
    .map_err(|err| {
        eprintln!("{}", err);
        exit(1);
    });
}
