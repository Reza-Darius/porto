use std::{collections::HashSet, path::Path};

use anyhow::{Result, anyhow};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use tracing::{debug, info, instrument};

use crate::{
    acme::{CERT_FILENAME, KEY_FILENAME, PortoTLS},
    utils::*,
};

/// Create the ACME order based on the given domain names. Inserts them on success
#[instrument(err, skip_all, fields(domains = ?domains))]
pub async fn issue_order(store: PortoTLS, domains: &[Domain]) -> Result<()> {
    info!("issuing new ACME order");

    let domains: Vec<_> = domains.to_vec();
    let account = &store.inner.account;

    let identifier: Vec<_> = domains
        .iter()
        .map(ToString::to_string)
        .map(Identifier::Dns)
        .collect();

    let mut order = account.new_order(&NewOrder::new(&identifier)).await?;

    // Pick the desired challenge type and prepare the response.
    let mut authorizations = order.authorizations();
    let mut tokens: HashSet<AcmeToken> = HashSet::new();

    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

        if challenge.token.is_empty() {
            return Err(anyhow!("http01 challenge token is empty"));
        }

        let token = AcmeToken::from_string(challenge.token.clone());

        store.register_challenge(token.clone(), challenge.key_authorization());

        // remembering the token for removal later
        tokens.insert(token);

        challenge.set_ready().await?;
    }

    let state = order.state();
    if state.status != OrderStatus::Pending {
        return Err(anyhow!("unexpected order state: {state:?}"));
    };

    // Exponentially back off until the order becomes ready or invalid.
    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(anyhow!("unexpected order status: {status:?}"));
    }

    // Finalize the order and print certificate chain, private key and account credentials.
    let key = KeyPem::from_string(order.finalize().await?);
    let cert = CertChainPem::from_string(order.poll_certificate(&RetryPolicy::default()).await?);

    {
        for token in tokens.into_iter() {
            store.remove_challenge(&token);
        }
    }

    write_order_to_disk(&store.inner.cred_path, &cert, &key)?;

    {
        // insert inside in memory cache
        let mut guard = store.inner.store.lock();

        for domain in domains.into_iter() {
            store.add_to_resolver(&domain, cert.clone(), key.clone())?;
            guard.insert(domain, (cert.clone(), key.clone()));
        }
    }

    info!("ACME order completed");
    debug!("\n{}\n{}", cert, key);

    Ok(())
}

fn write_order_to_disk(path: impl AsRef<Path>, cert: &CertChainPem, key: &KeyPem) -> Result<()> {
    std::fs::write(path.as_ref().join(CERT_FILENAME), cert.as_bytes())?;
    std::fs::write(path.as_ref().join(KEY_FILENAME), key.as_bytes())?;
    Ok(())
}
