use std::path::Path;

use anyhow::{Result, anyhow};
use bincode::config::Configuration;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use tracing::{debug, instrument, warn};

use crate::tls::acme::AcmeMode;

static BINCODE_CONFIG: Configuration = bincode::config::standard();

/// attempts to open a "cred_path/account" file otherwise creates a new account
///
/// if debug == true it will create a pebble test account
#[instrument(err, skip_all)]
pub async fn get_account(mode: AcmeMode, acc_cred_path: impl AsRef<Path>) -> Result<Account> {
    debug!("getting ACME account");

    match mode {
        AcmeMode::Debug => create_test_acc().await,
        AcmeMode::Staging => {
            match acc_from_file(&acc_cred_path).await {
                Ok(acc) => Ok(acc),
                Err(e) => {
                    warn!(err = %e, "couldnt read account from disk");
                    create_acc(acc_cred_path, LetsEncrypt::Staging).await
                }
            }
        }
        AcmeMode::Prod => {
            match acc_from_file(&acc_cred_path).await {
                Ok(acc) => Ok(acc),
                Err(e) => {
                    warn!(err = %e, "couldnt read account from disk");
                    create_acc(acc_cred_path, LetsEncrypt::Production).await
                }
            }
        }
    }
}

async fn create_acc(path: impl AsRef<Path>, staging: LetsEncrypt) -> Result<Account> {
    debug!("creating new Let's Encrypt account");

    let (account, creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[], // could be some email
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // staging enviroment is for testing purposes
            staging.url().to_string(),
            None,
        )
        .await?;

    let data =
        bincode::serde::encode_to_vec::<AccountCredentials, Configuration>(creds, BINCODE_CONFIG)?;
    std::fs::write(path, data)?;

    Ok(account)
}

async fn create_test_acc() -> Result<Account> {
    debug!("creating new testing account");

    let acc = NewAccount {
        contact: &["mailto:test@email.com"],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let acc = Account::builder_with_root("pebble.minica.pem")?
        .create(&acc, "https://localhost:14000/dir".to_string(), None)
        .await?;
    debug!("we got an account");

    Ok(acc.0)
}

async fn acc_from_file(path: impl AsRef<Path>) -> Result<Account> {
    let path = Path::new(path.as_ref()).join("account");

    if path.exists() {
        debug!("reading ACME acc from file");

        let file = std::fs::read(path)?;

        let (creds, _) = bincode::serde::decode_from_slice::<AccountCredentials, Configuration>(
            &file,
            BINCODE_CONFIG,
        )?;

        let acc = Account::builder()?.from_credentials(creds).await?;

        return Ok(acc);
    }
    Err(anyhow!("credentials dont exist"))
}
