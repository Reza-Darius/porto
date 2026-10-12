use std::path::Path;

use anyhow::{Result, anyhow};
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use tracing::{debug, instrument, trace, warn};

use crate::tls::acme::AcmeProvider;

const ACCOUNT_FILENAME: &str = "account.json";

/// attempts to open a "cred_path/account.json" file otherwise creates a new account
///
/// if debug == true it will create a pebble test account
#[instrument(skip_all)]
pub async fn get_account(cred_path: impl AsRef<Path>, mode: AcmeProvider) -> Result<Account> {
    let cred_path = cred_path.as_ref();

    if !cred_path.is_dir() {
        return Err(anyhow!("passed path isnt a directory"));
    }

    let path = cred_path.join(ACCOUNT_FILENAME);

    match mode {
        AcmeProvider::Pebble(url) => create_pebble_acc(url, &path).await,
        AcmeProvider::LetsEncrypt(staging) => match read_acc_disk(&path).await {
            Ok(acc) => Ok(acc),
            Err(e) => {
                warn!(%e, "couldnt read account from disk");
                create_letsencrypt_acc(&path, staging).await
            }
        },
    }
}

async fn create_letsencrypt_acc(
    acc_path: impl AsRef<Path>,
    staging: LetsEncrypt,
) -> Result<Account> {
    debug!("creating new Let's Encrypt account");

    let (account, creds) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[], // could be some email
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            staging.url().to_string(),
            None,
        )
        .await?;

    write_acc_disk(&creds, acc_path).await?;

    Ok(account)
}

async fn create_pebble_acc(url: impl Into<String>, acc_path: impl AsRef<Path>) -> Result<Account> {
    debug!("creating new testing account");

    let acc = NewAccount {
        contact: &["mailto:test@email.com"],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (acc, creds) = Account::builder_with_root("tests/pebble/pebble.minica.pem")?
        .create(&acc, url.into(), None)
        .await?;

    write_acc_disk(&creds, acc_path).await?;

    debug!("we got an account");

    Ok(acc)
}

async fn read_acc_disk(path: impl AsRef<Path>) -> Result<Account> {
    trace!("reading ACME acc from file");

    let file = std::fs::read(path)?;
    let creds = serde_json::from_slice::<AccountCredentials>(&file)?;
    let acc = Account::builder()?.from_credentials(creds).await?;

    Ok(acc)
}

async fn write_acc_disk(cred: &AccountCredentials, acc_path: impl AsRef<Path>) -> Result<()> {
    trace!("writing ACME acc to file");

    let json = serde_json::to_vec_pretty(cred)?;
    tokio::fs::write(acc_path, json).await.map_err(Into::into)
}
