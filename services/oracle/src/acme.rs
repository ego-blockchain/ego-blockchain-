use anyhow::{anyhow, Context};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

pub type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CertStatus {
    Pending,
    Ready { cert_pem: String, issued_at: i64 },
    Failed { reason: String },
}

const RENEW_AFTER_SECS: i64 = 60 * 86_400;

pub struct AcmeState {
    pub challenges: ChallengeMap,
    certs: Arc<RwLock<HashMap<String, CertStatus>>>,
}

impl AcmeState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            certs: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn status(&self, domain: &str) -> Option<CertStatus> {
        self.certs.read().await.get(domain).cloned()
    }

    pub async fn request(self: &Arc<Self>, domain: String, csr_der: Vec<u8>) {
        {
            let now = chrono::Utc::now().timestamp();
            let mut c = self.certs.write().await;
            match c.get(&domain) {
                Some(CertStatus::Pending) => return,
                Some(CertStatus::Ready { issued_at, .. }) if now - issued_at < RENEW_AFTER_SECS => return,
                _ => {}
            }
            c.insert(domain.clone(), CertStatus::Pending);
        }
        let challenges = self.challenges.clone();
        let certs      = self.certs.clone();
        tokio::spawn(async move {
            let result = issue_cert(&domain, &csr_der, &challenges).await;
            challenges.write().await.remove(&format!("_acme-challenge.{}", domain));
            match result {
                Ok(cert_pem) => {
                    tracing::info!("[ACME] Cert issued for {}", domain);
                    let issued_at = chrono::Utc::now().timestamp();
                    certs.write().await.insert(domain, CertStatus::Ready { cert_pem, issued_at });
                }
                Err(e) => {
                    tracing::error!("[ACME] Cert failed for {}: {}", domain, e);
                    certs.write().await.insert(domain, CertStatus::Failed { reason: e.to_string() });
                }
            }
        });
    }
}

async fn issue_cert(domain: &str, csr_der: &[u8], challenges: &ChallengeMap) -> anyhow::Result<String> {
    tracing::info!("[ACME] Starting DNS-01 for {}", domain);

    let (account, _) = Account::create(
        &NewAccount {
            contact:                  &[],
            terms_of_service_agreed:  true,
            only_return_existing:     false,
        },
        LetsEncrypt::Production.url(),
        None,
    )
    .await
    .context("create ACME account")?;

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.to_string())],
        })
        .await
        .context("new order")?;

    let authorizations = order.authorizations().await.context("get authorizations")?;

    for authz in &authorizations {
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| anyhow!("no DNS-01 challenge in authorization"))?;

        let key_auth  = order.key_authorization(challenge);
        let txt_value = key_auth.dns_value();
        let txt_key   = format!("_acme-challenge.{}", domain);

        tracing::info!("[ACME] Serving TXT {} = {}", txt_key, txt_value);
        challenges.write().await.insert(txt_key, txt_value);

        order
            .set_challenge_ready(&challenge.url)
            .await
            .context("set challenge ready")?;
    }

    for attempt in 0..24u8 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        order.refresh().await.context("refresh order")?;
        match order.state().status {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid => {
                return Err(anyhow!("Let's Encrypt invalidated the order"));
            }
            _ => {
                tracing::debug!("[ACME] Waiting for validation (attempt {})", attempt + 1);
            }
        }
    }

    if !matches!(
        order.state().status,
        OrderStatus::Ready | OrderStatus::Valid
    ) {
        return Err(anyhow!("validation timed out after 120s"));
    }

    order.finalize(csr_der).await.context("finalize order")?;

    let mut cert_chain_pem = None;
    for _ in 0..40u8 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(cert) = order.certificate().await.context("poll certificate")? {
            cert_chain_pem = Some(cert);
            break;
        }
    }
    let cert_chain_pem = cert_chain_pem.ok_or_else(|| anyhow!("the certificate was not ready after 120s"))?;

    challenges
        .write()
        .await
        .remove(&format!("_acme-challenge.{}", domain));

    Ok(cert_chain_pem)
}
