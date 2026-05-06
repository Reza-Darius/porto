use std::path::Path;

use anyhow::{Result, anyhow};
use bincode::config::Configuration;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use tracing::{debug, info, instrument, warn};

#[instrument(err)]
pub async fn get_acme_test_acc() -> Result<Account> {
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

/// attempts to open a "cred_path/account" file otherwise creates a new account
#[instrument(err, skip_all)]
pub async fn get_account(cred_path: impl AsRef<Path>) -> Result<Account> {
    let path = Path::new(cred_path.as_ref()).join("account");
    let config = bincode::config::standard();

    info!("getting ACME account");

    match read_from_file(&path, config).await {
        Ok(acc) => Ok(acc),
        Err(e) => {
            warn!(err = %e, "couldnt read account from disk");
            create_new_acc(&path, config).await
        }
    }
}

async fn read_from_file(path: &Path, config: Configuration) -> Result<Account> {
    if path.exists() {
        debug!("reading ACME acc from file");

        let file = tokio::fs::read(&path).await?;

        let (creds, _) =
            bincode::serde::decode_from_slice::<AccountCredentials, Configuration>(&file, config)?;

        let acc = Account::builder()?.from_credentials(creds).await?;

        return Ok(acc);
    }
    Err(anyhow!("credentials dont exist"))
}

async fn create_new_acc(path: &Path, config: Configuration) -> Result<Account> {
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

    let data = bincode::serde::encode_to_vec::<AccountCredentials, Configuration>(creds, config)?;
    tokio::fs::write(path, data).await?;

    Ok(account)
}
