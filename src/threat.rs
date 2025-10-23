use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{RwLock, OnceCell};

use crate::redis::RedisManager;

/// Custom deserializer for optional datetime fields that can be empty strings or missing
fn deserialize_optional_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    // Try to deserialize as Option<String> first
    match Option::<String>::deserialize(deserializer)? {
        Some(s) => {
            if s.is_empty() {
                Ok(None)
            } else {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| Some(dt.with_timezone(&Utc)))
                    .map_err(serde::de::Error::custom)
            }
        }
        None => Ok(None),
    }
}

/// Threat intelligence response from Arx Ignis API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub schema_version: String,
    pub tenant_id: String,
    pub ip: String,
    pub intel: ThreatIntel,
    pub context: ThreatContext,
    pub advice: String,
    pub ttl_s: u64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub score: u32,
    pub confidence: f64,
    pub score_version: String,
    pub categories: Vec<String>,
    pub tags: Vec<String>,
    #[serde(deserialize_with = "deserialize_optional_datetime")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "deserialize_optional_datetime")]
    pub last_seen: Option<DateTime<Utc>>,
    pub source_count: u32,
    pub reason_code: String,
    pub reason_summary: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub asn: u32,
    pub org: String,
    pub ip_version: u8,
    pub geo: GeoInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: String,
    pub iso_code: String,
    #[serde(rename = "asniso_code")]
    pub asn_iso_code: String,
}

/// Cached threat data with expiration
#[derive(Debug, Clone)]
pub struct CachedThreatData {
    pub data: ThreatResponse,
    pub expires_at: Instant,
}

/// WAF fields extracted from threat data
#[derive(Debug, Clone)]
pub struct WafFields {
    pub ip_src_country: String,
    pub ip_src_asn: u32,
    pub ip_src_asn_org: String,
    pub ip_src_asn_country: String,
    pub threat_score: u32,
    pub threat_advice: String,
}

impl From<&ThreatResponse> for WafFields {
    fn from(threat: &ThreatResponse) -> Self {
        Self {
            ip_src_country: threat.context.geo.country.clone(),
            ip_src_asn: threat.context.asn,
            ip_src_asn_org: threat.context.org.clone(),
            ip_src_asn_country: threat.context.geo.asn_iso_code.clone(),
            threat_score: threat.intel.score,
            threat_advice: threat.advice.clone(),
        }
    }
}

/// Threat intelligence client with L1 (in-memory) and L2 (Redis) caching
pub struct ThreatClient {
    base_url: String,
    api_key: String,
    l1_cache: Arc<RwLock<HashMap<String, CachedThreatData>>>,
}

impl ThreatClient {
    pub fn new(
        base_url: String,
        api_key: String,
    ) -> Self {
        Self {
            base_url,
            api_key,
            l1_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get threat intelligence for an IP address with caching
    pub async fn get_threat_intel(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        // Check L1 cache first (30 seconds TTL)
        if let Some(cached) = self.get_l1_cache(ip).await {
            if cached.expires_at > Instant::now() {
                log::debug!("Threat data for {} found in L1 cache", ip);
                return Ok(Some(cached.data));
            } else {
                // Remove expired entry
                self.remove_l1_cache(ip).await;
            }
        }

        // Check L2 cache (Redis) with TTL from API response
        if let Some(cached) = self.get_l2_cache(ip).await? {
            log::debug!("Threat data for {} found in L2 cache", ip);
            // Store in L1 cache for faster access
            self.set_l1_cache(ip, &cached).await;
            return Ok(Some(cached));
        }

        // Fetch from API
        match self.fetch_from_api(ip).await {
            Ok(Some(threat_data)) => {
                log::debug!("Threat data for {} fetched from API", ip);

                // Store in both caches
                self.set_l1_cache(ip, &threat_data).await;
                if let Err(e) = self.set_l2_cache(ip, &threat_data).await {
                    log::warn!("Failed to store threat data in L2 cache: {}", e);
                }

                Ok(Some(threat_data))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                log::error!("Failed to fetch threat data for {}: {}", ip, e);
                Err(e)
            }
        }
    }

    /// Get WAF fields for an IP address
    pub async fn get_waf_fields(&self, ip: &str) -> Result<Option<WafFields>> {
        if let Some(threat_data) = self.get_threat_intel(ip).await? {
            Ok(Some(WafFields::from(&threat_data)))
        } else {
            Ok(None)
        }
    }

    /// Fetch threat data from Arx Ignis API
    async fn fetch_from_api(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        let url = format!("{}/threat?ip={}", self.base_url, ip);

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", &self.api_key))
            .send()
            .await
            .context("Failed to send HTTP request")?;

        if response.status() == 404 {
            // IP not found in threat database
            return Ok(None);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Unable to read response body".to_string());
            log::error!("API request failed with status: {}, body: {}", status, body);
            return Err(anyhow::anyhow!(
                "API request failed with status: {}",
                status
            ));
        }

        let response_text = response.text().await
            .context("Failed to read response body")?;

        log::debug!("API response body: {}", response_text);

        let threat_data: ThreatResponse = serde_json::from_str(&response_text)
            .context("Failed to parse JSON response")?;

        Ok(Some(threat_data))
    }

    /// Get data from L1 cache (in-memory)
    async fn get_l1_cache(&self, ip: &str) -> Option<CachedThreatData> {
        let cache = self.l1_cache.read().await;
        cache.get(ip).cloned()
    }

    /// Set data in L1 cache (30 seconds TTL)
    async fn set_l1_cache(&self, ip: &str, data: &ThreatResponse) {
        let mut cache = self.l1_cache.write().await;
        cache.insert(
            ip.to_string(),
            CachedThreatData {
                data: data.clone(),
                expires_at: Instant::now() + Duration::from_secs(30),
            },
        );
    }

    /// Remove expired data from L1 cache
    async fn remove_l1_cache(&self, ip: &str) {
        let mut cache = self.l1_cache.write().await;
        cache.remove(ip);
    }

    /// Get data from L2 cache (Redis)
    async fn get_l2_cache(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        let redis_manager = match RedisManager::get() {
            Ok(manager) => manager,
            Err(_) => return Ok(None),
        };

        let key = format!("{}:threat:{}", redis_manager.create_namespace("threat"), ip);
        let mut redis = redis_manager.get_connection();

        match redis.get::<_, Option<String>>(&key).await {
            Ok(Some(data)) => {
                match serde_json::from_str::<ThreatResponse>(&data) {
                    Ok(threat_data) => Ok(Some(threat_data)),
                    Err(e) => {
                        log::warn!("Failed to deserialize cached threat data for key {}: {}. Clearing cache entry.", key, e);
                        // Clear the invalid cache entry
                        let _: () = redis.del(&key).await.unwrap_or_default();
                        Ok(None)
                    }
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                log::warn!("Redis get error for key {}: {}", key, e);
                Ok(None)
            }
        }
    }

    /// Set data in L2 cache (Redis) with TTL from API response
    async fn set_l2_cache(&self, ip: &str, data: &ThreatResponse) -> Result<()> {
        let redis_manager = match RedisManager::get() {
            Ok(manager) => manager,
            Err(_) => return Ok(()),
        };

        let key = format!("{}:threat:{}", redis_manager.create_namespace("threat"), ip);
        let mut redis = redis_manager.get_connection();

        let json_data = serde_json::to_string(data)
            .context("Failed to serialize threat data")?;

        let _: () = redis
            .set_ex(&key, json_data, data.ttl_s)
            .await
            .context("Failed to store threat data in Redis")?;

        Ok(())
    }

    /// Clean up expired entries from L1 cache
    pub async fn cleanup_l1_cache(&self) {
        let mut cache = self.l1_cache.write().await;
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);
    }
}

/// Global threat client instance
static THREAT_CLIENT: OnceCell<Arc<ThreatClient>> = OnceCell::const_new();

/// Initialize the global threat client
pub async fn init_threat_client(
    base_url: String,
    api_key: String,
) -> Result<()> {
    let client = Arc::new(ThreatClient::new(base_url, api_key));

    THREAT_CLIENT.set(client)
        .map_err(|_| anyhow::anyhow!("Failed to initialize threat client"))?;

    Ok(())
}

/// Get threat intelligence for an IP address
pub async fn get_threat_intel(ip: &str) -> Result<Option<ThreatResponse>> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.get_threat_intel(ip).await
}

/// Get WAF fields for an IP address
pub async fn get_waf_fields(ip: &str) -> Result<Option<WafFields>> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.get_waf_fields(ip).await
}

/// Start periodic L1 cache cleanup task
pub async fn start_cache_cleanup_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Some(client) = THREAT_CLIENT.get() {
                client.cleanup_l1_cache().await;
            }
        }
    });
}
