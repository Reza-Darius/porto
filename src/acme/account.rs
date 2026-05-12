use std::path::Path;

use anyhow::{Result, anyhow};
use bincode::config::Configuration;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use tracing::{debug, info, instrument, warn};

static BINCODE_CONFIG: Configuration = bincode::config::standard();

/// attempts to open a "cred_path/account" file otherwise creates a new account
///
/// if debug = true it will create a pebble test account
#[instrument(err, skip_all)]
pub async fn get_account(debug: bool, cred_path: impl AsRef<Path>) -> Result<Account> {
    if debug {
        return new_test_acc().await;
    }

    let path = Path::new(cred_path.as_ref()).join("account");

    info!("getting ACME account");

    match read_from_file(&path).await {
        Ok(acc) => Ok(acc),
        Err(e) => {
            warn!(err = %e, "couldnt read account from disk");
            create_new_acc(&path).await
        }
    }
}

async fn read_from_file(path: &Path) -> Result<Account> {
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

async fn create_new_acc(path: &Path) -> Result<Account> {
    debug!("creating new account");

    let (account, creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[], // could be some email
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            // staging enviroment is for testing purposes
            LetsEncrypt::Staging.url().to_owned(),
            None,
        )
        .await?;

    let data =
        bincode::serde::encode_to_vec::<AccountCredentials, Configuration>(creds, BINCODE_CONFIG)?;
    std::fs::write(path, data)?;

    Ok(account)
}

async fn new_test_acc() -> Result<Account> {
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
