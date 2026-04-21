use anyhow::{anyhow, Context};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{Certificate, CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

pub type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CertStatus {
    Pending,
    Ready { cert_pem: String, key_pem: String },
    Failed { reason: String },
}

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

    pub async fn request(self: &Arc<Self>, domain: String) {
        {
            let mut c = self.certs.write().await;
            match c.get(&domain) {
                Some(CertStatus::Ready { .. }) | Some(CertStatus::Pending) => return,
                _ => {}
            }
            c.insert(domain.clone(), CertStatus::Pending);
        }
        let challenges = self.challenges.clone();
        let certs      = self.certs.clone();
        tokio::spawn(async move {
            match issue_cert(&domain, &challenges).await {
                Ok((cert_pem, key_pem)) => {
                    tracing::info!("[ACME] Cert issued for {}", domain);
                    certs.write().await.insert(domain, CertStatus::Ready { cert_pem, key_pem });
                }
                Err(e) => {
                    tracing::error!("[ACME] Cert failed for {}: {}", domain, e);
                    certs.write().await.insert(domain, CertStatus::Failed { reason: e.to_string() });
                }
            }
        });
    }
}

async fn issue_cert(domain: &str, challenges: &ChallengeMap) -> anyhow::Result<(String, String)> {
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

    let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).context("generate key pair")?;
    let mut params = CertificateParams::new(vec![domain.to_string()]);
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert    = Certificate::from_params(params).context("build cert params")?;
    let csr_der = cert.serialize_request_der(&key_pair).context("serialize CSR")?;

    order.finalize(&csr_der).await.context("finalize order")?;

    let cert_chain_pem = loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Some(cert) = order.certificate().await.context("poll certificate")? {
            break cert;
        }
    };

    challenges
        .write()
        .await
        .remove(&format!("_acme-challenge.{}", domain));

    Ok((cert_chain_pem, key_pair.serialize_pem()))
}
