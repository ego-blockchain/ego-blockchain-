use anyhow::{anyhow, Context};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};

pub type ChallengeMap = Arc<RwLock<HashMap<String, String>>>;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CertStatus {
    Pending,
    Ready { cert_pem: String, issued_at: i64 },
    Failed { reason: String },
}

const RENEW_AFTER_SECS: i64 = 60 * 86_400;
const KEEP_READY_SECS: i64 = 7 * 86_400;
const KEEP_OTHER_SECS: i64 = 3_600;

pub struct AcmeState {
    pub challenges: ChallengeMap,
    certs: Arc<RwLock<HashMap<String, (i64, CertStatus, Vec<u8>)>>>,
    account: Arc<Mutex<Option<Account>>>,
    account_path: Option<PathBuf>,
}

fn keep(now: i64, at: i64, status: &CertStatus) -> bool {
    match status {
        CertStatus::Ready { .. } => now - at < KEEP_READY_SECS,
        _ => now - at < KEEP_OTHER_SECS,
    }
}

impl AcmeState {
    pub fn new(account_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            certs: Arc::new(RwLock::new(HashMap::new())),
            account: Arc::new(Mutex::new(None)),
            account_path,
        })
    }

    pub async fn status(&self, domain: &str) -> Option<CertStatus> {
        self.certs.read().await.get(domain).map(|(_, s, _)| s.clone())
    }

    pub async fn request(self: &Arc<Self>, domain: String, identifiers: Vec<String>, csr_der: Vec<u8>) {
        {
            let now = chrono::Utc::now().timestamp();
            let mut c = self.certs.write().await;
            c.retain(|_, (at, s, _)| keep(now, *at, s));
            match c.get(&domain) {
                Some((_, CertStatus::Pending, _)) => return,
                Some((_, CertStatus::Ready { issued_at, .. }, old)) if old == &csr_der && now - issued_at < RENEW_AFTER_SECS => return,
                _ => {}
            }
            c.insert(domain.clone(), (now, CertStatus::Pending, csr_der.clone()));
        }
        let me = self.clone();
        tokio::spawn(async move {
            let result = me.issue(&identifiers, &csr_der).await;
            {
                let mut ch = me.challenges.write().await;
                for name in &identifiers {
                    ch.remove(&format!("_acme-challenge.{}", name));
                }
            }
            let now = chrono::Utc::now().timestamp();
            let status = match result {
                Ok(cert_pem) => {
                    tracing::info!("[ACME] Cert issued for {}", identifiers.join(", "));
                    CertStatus::Ready { cert_pem, issued_at: now }
                }
                Err(e) => {
                    tracing::error!("[ACME] Cert failed for {}: {:#}", identifiers.join(", "), e);
                    CertStatus::Failed { reason: format!("{e:#}") }
                }
            };
            me.certs.write().await.insert(domain, (now, status, csr_der));
        });
    }

    async fn account(&self) -> anyhow::Result<Account> {
        let mut slot = self.account.lock().await;
        if let Some(a) = slot.as_ref() {
            return Ok(a.clone());
        }
        if let Some(path) = &self.account_path {
            if let Ok(raw) = std::fs::read_to_string(path) {
                if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&raw) {
                    let a = Account::from_credentials(creds).await.context("load the saved ACME account")?;
                    *slot = Some(a.clone());
                    return Ok(a);
                }
            }
        }
        let (a, creds) = Account::create(
            &NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false },
            LetsEncrypt::Production.url(),
            None,
        )
        .await
        .context("create ACME account")?;
        if let Some(path) = &self.account_path {
            let saved = serde_json::to_vec(&creds).map_err(anyhow::Error::from).and_then(|data| {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let tmp = path.with_extension("json.tmp");
                std::fs::write(&tmp, data)?;
                std::fs::rename(&tmp, path)?;
                Ok(())
            });
            if let Err(e) = saved {
                tracing::error!("[ACME] Saving the ACME account to {} FAILED: {:#}", path.display(), e);
            }
        }
        *slot = Some(a.clone());
        Ok(a)
    }

    async fn issue(&self, identifiers: &[String], csr_der: &[u8]) -> anyhow::Result<String> {
        tracing::info!("[ACME] Starting DNS-01 for {}", identifiers.join(", "));
        let account = self.account().await?;
        let ids: Vec<Identifier> = identifiers.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account.new_order(&NewOrder { identifiers: &ids }).await.context("new order")?;

        let authorizations = order.authorizations().await.context("get authorizations")?;
        for authz in &authorizations {
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let Identifier::Dns(name) = &authz.identifier;
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .ok_or_else(|| anyhow!("no DNS-01 challenge for {name}"))?;
            let txt_key = format!("_acme-challenge.{}", name);
            let txt_value = order.key_authorization(challenge).dns_value();
            tracing::info!("[ACME] Serving TXT {} = {}", txt_key, txt_value);
            self.challenges.write().await.insert(txt_key, txt_value);
            order.set_challenge_ready(&challenge.url).await.context("set challenge ready")?;
        }

        for attempt in 0..24u8 {
            order.refresh().await.context("refresh order")?;
            match order.state().status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => return Err(anyhow!("Let's Encrypt could not confirm the domain (its DNS must point at Ego's nameservers)")),
                _ => tracing::debug!("[ACME] Waiting for validation (attempt {})", attempt + 1),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if !matches!(order.state().status, OrderStatus::Ready | OrderStatus::Valid) {
            return Err(anyhow!("validation timed out after 120s"));
        }

        if order.state().status == OrderStatus::Ready {
            order.finalize(csr_der).await.context("finalize order")?;
        }
        for _ in 0..40u8 {
            if let Some(cert) = order.certificate().await.context("poll certificate")? {
                return Ok(cert);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        Err(anyhow!("the certificate was not ready after 120s"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_requests_are_forgotten_so_memory_stays_small() {
        let now = 1_800_000_000;
        let ready = CertStatus::Ready { cert_pem: String::new(), issued_at: now };
        assert!(keep(now, now - 86_400, &ready));
        assert!(!keep(now, now - KEEP_READY_SECS, &ready));
        assert!(keep(now, now - 60, &CertStatus::Failed { reason: String::new() }));
        assert!(!keep(now, now - KEEP_OTHER_SECS, &CertStatus::Failed { reason: String::new() }));
        assert!(!keep(now, now - KEEP_OTHER_SECS, &CertStatus::Pending));
    }
}
