use std::path::Path;

use anyhow::Result;
use bincode::config::Configuration;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use tracing::{debug, error, info, instrument};

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

#[instrument(err, skip_all)]
pub async fn get_acme_acc(cred_path: impl AsRef<Path>) -> Result<Account> {
    let path = Path::new(cred_path.as_ref()).join("account");
    let config = bincode::config::standard();

    if path.exists() {
        info!("retrieving ACME acc credentials from file");

        if let Ok(file) = tokio::fs::read(&path)
            .await
            .inspect_err(|e| error!(%e, "couldnt retrieve acc credentials from disk"))
        {
            let (creds, _) = bincode::serde::decode_from_slice::<AccountCredentials, Configuration>(
                &file, config,
            )?;

            let acc = Account::builder()?.from_credentials(creds).await?;

            return Ok(acc);
        };
    }

    info!("requesting new ACME account");

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
