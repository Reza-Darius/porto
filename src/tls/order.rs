use anyhow::{Result, anyhow};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use tracing::{debug, instrument};

use super::cert_types::*;
use crate::tls::challenge::ChallStoreHandle;
use crate::utils::*;

/// Create the ACME order based on the given domain names. Inserts them on success
#[instrument(skip_all)]
pub async fn issue_order(
    acc: &Account,
    chall_store: &ChallStoreHandle,
    domains: impl Iterator<Item = &Domain>,
) -> Result<(CertChainPem, KeyPem)> {
    let identifier: Vec<_> = domains
        .map(ToString::to_string)
        .map(Identifier::Dns)
        .collect();

    debug!(?identifier, "issuing new ACME order");

    let mut order = acc.new_order(&NewOrder::new(&identifier)).await?;

    let mut authorizations = order.authorizations();

    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        // Pick the desired challenge type and prepare the response.
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;

        if challenge.token.is_empty() {
            return Err(anyhow!("http01 challenge token is empty"));
        }

        // put token in the chall store
        let token = AcmeToken::from_string(challenge.token.clone());
        chall_store.insert_challenge(token, challenge.key_authorization());

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

    // Finalize the order
    let key = KeyPem::from_string(order.finalize().await?);
    let cert = CertChainPem::from_string(order.poll_certificate(&RetryPolicy::default()).await?);

    debug!("ACME order completed");
    // debug!("\n{}\n{}", cert, key);

    chall_store.clear();

    Ok((cert, key))
}
