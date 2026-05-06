use std::collections::HashSet;

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
pub async fn issue_order(store: PortoTLS, account: &Account, domains: &[Domain]) -> Result<()> {
    info!("issuing new ACME order");

    let domains: Vec<_> = domains.to_vec();

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

        let token = AcmeToken::from_str(challenge.token.clone());

        store
            .inner
            .pending_challenges
            .lock()
            .insert(token.clone(), challenge.key_authorization());

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
    let key = KeyPem::from_str(order.finalize().await?);
    let cert = CertChainPem::from_str(order.poll_certificate(&RetryPolicy::default()).await?);

    {
        // remove from pending tokens
        let mut guard = store.inner.pending_challenges.lock();
        for token in tokens.into_iter() {
            guard.remove(&token);
        }
    }

    tokio::fs::write(
        store.inner.cred_path.join(KEY_FILENAME),
        key.as_str().as_bytes(),
    )
    .await?;

    tokio::fs::write(
        store.inner.cred_path.join(CERT_FILENAME),
        cert.as_str().as_bytes(),
    )
    .await?;

    {
        // insert inside in memory cache
        let mut guard = store.inner.certs.lock();

        for domain in domains.into_iter() {
            store.add_to_resolver(&domain, cert.clone(), key.clone())?;
            guard.insert(domain, (cert.clone(), key.clone()));
        }
    }

    info!("ACME order completed");
    debug!("\n{}\n{}", cert, key);

    Ok(())
}
