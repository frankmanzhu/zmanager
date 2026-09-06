//! Online intermediate certificate resolver and fetcher (design §7, Z4).
//!
//! Fetches missing platform intermediate certificates from
//! `GET /v1/trust/intermediates` and `GET /v1/trust/intermediates/{fingerprint}/pem`,
//! storing them into the local `TzapIntermediateCache`.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use zmanager_core::trust::{TzapIntermediateCache, TzapIntermediateResolveError, TzapIntermediateResolver};

use crate::auth_client::{
    TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpTransport, TzapAuthRequestOptions, TzapBearerToken,
};
use crate::http_client::{require_success, send_json_request};

/// Resolver that checks the local `TzapIntermediateCache` and fetches from
/// the platform intermediate distribution endpoint on cache misses.
#[derive(Clone)]
pub struct TzapOnlineIntermediateResolver<T> {
    cache: TzapIntermediateCache,
    service_base_url: Option<String>,
    transport: T,
}

impl<T> fmt::Debug for TzapOnlineIntermediateResolver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TzapOnlineIntermediateResolver")
            .field("cache", &self.cache)
            .field("service_base_url", &self.service_base_url)
            .finish_non_exhaustive()
    }
}

impl<T> TzapOnlineIntermediateResolver<T> {
    pub fn new(cache: TzapIntermediateCache, service_base_url: Option<String>, transport: T) -> Self {
        Self { cache, service_base_url, transport }
    }

    #[must_use]
    pub fn cache(&self) -> &TzapIntermediateCache {
        &self.cache
    }
}

#[cfg(feature = "reqwest-transport")]
impl TzapOnlineIntermediateResolver<crate::reqwest_transport::ReqwestTransport> {
    #[must_use]
    pub fn with_reqwest(cache: TzapIntermediateCache, service_base_url: Option<String>) -> Self {
        Self::new(cache, service_base_url, crate::reqwest_transport::ReqwestTransport)
    }
}

impl<T: TzapAuthHttpTransport + Send + Sync + 'static> TzapIntermediateResolver for TzapOnlineIntermediateResolver<T> {
    fn resolve_intermediate(&self, aki: &[u8]) -> Result<Option<Vec<u8>>, TzapIntermediateResolveError> {
        // 1. Check local cache first
        if let Ok(Some(der)) = self.cache.get_by_aki(aki) {
            return Ok(Some(der));
        }

        let aki_b64 = URL_SAFE_NO_PAD.encode(aki);

        // 2. If no service URL configured, report offline miss immediately
        let Some(service_url) = self.service_base_url.as_deref().filter(|url| !url.trim().is_empty()) else {
            return Err(TzapIntermediateResolveError::OfflineMiss {
                issuer_key_identifier: aki_b64,
                reason: "no service URL configured".to_owned(),
            });
        };

        // 3. Fetch intermediate summaries list from GET /v1/trust/intermediates
        let response = send_json_request(
            &self.transport,
            TzapAuthHttpMethod::Get,
            service_url,
            "/v1/trust/intermediates",
            None::<TzapBearerToken>,
            None,
        )
        .map_err(|error| TzapIntermediateResolveError::OfflineMiss {
            issuer_key_identifier: aki_b64.clone(),
            reason: error.to_string(),
        })?;

        let response = require_success(response, |status_code, _| TzapAuthError::HttpStatus { status_code })
            .map_err(|error| TzapIntermediateResolveError::OfflineMiss {
                issuer_key_identifier: aki_b64.clone(),
                reason: error.to_string(),
            })?;

        let summaries: Value = serde_json::from_slice(&response.body).map_err(|error| {
            TzapIntermediateResolveError::Transport(format!("invalid intermediate summaries JSON: {error}"))
        })?;

        let summaries_array = summaries.as_array().ok_or_else(|| {
            TzapIntermediateResolveError::Transport("server returned non-array intermediates".to_owned())
        })?;

        // Find summary with matching keyIdentifier (Subject Key Identifier)
        let matching_summary = summaries_array.iter().find(|item| {
            item.get("keyIdentifier")
                .or_else(|| item.get("key_identifier"))
                .and_then(Value::as_str)
                .is_some_and(|kid| kid == aki_b64)
        });

        let Some(summary) = matching_summary else {
            return Ok(None);
        };

        let pem_url = summary
            .get("certificatePemUrl")
            .or_else(|| summary.get("certificate_pem_url"))
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                summary
                    .get("certificateFingerprint")
                    .or_else(|| summary.get("certificate_fingerprint"))
                    .and_then(Value::as_str)
                    .map(|fp| format!("/v1/trust/intermediates/{fp}/pem"))
            })
            .ok_or_else(|| TzapIntermediateResolveError::Transport("missing certificatePemUrl".to_owned()))?;

        let full_pem_url = if pem_url.starts_with("http://") || pem_url.starts_with("https://") {
            pem_url
        } else {
            format!("{}/{}", service_url.trim_end_matches('/'), pem_url.trim_start_matches('/'))
        };

        let request = TzapAuthHttpRequest {
            method: TzapAuthHttpMethod::Get,
            url: full_pem_url,
            bearer_token: None,
            body: None,
            options: TzapAuthRequestOptions::default(),
        };

        let pem_response = self.transport.send(&request).map_err(|error| TzapIntermediateResolveError::OfflineMiss {
            issuer_key_identifier: aki_b64.clone(),
            reason: error.to_string(),
        })?;

        let pem_response = require_success(pem_response, |status_code, _| TzapAuthError::HttpStatus { status_code })
            .map_err(|error| TzapIntermediateResolveError::OfflineMiss {
                issuer_key_identifier: aki_b64.clone(),
                reason: error.to_string(),
            })?;

        // Convert PEM to DER
        let pem_str = std::str::from_utf8(&pem_response.body).map_err(|error| {
            TzapIntermediateResolveError::InvalidCertificate(format!("PEM is not valid UTF-8: {error}"))
        })?;

        let x509 = openssl::x509::X509::from_pem(pem_str.as_bytes()).map_err(|error| {
            TzapIntermediateResolveError::InvalidCertificate(format!("failed to parse certificate PEM: {error}"))
        })?;
        let der = x509.to_der().map_err(|error| {
            TzapIntermediateResolveError::InvalidCertificate(format!("failed to encode certificate DER: {error}"))
        })?;

        // Save to cache
        self.cache.store(&der).map_err(|error| {
            TzapIntermediateResolveError::Storage(format!("failed to store certificate in cache: {error}"))
        })?;

        Ok(Some(der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use crate::auth_client::TzapAuthHttpResponse;
    use zmanager_core::backend_test_support::x509_factory::{intermediate_certificate, p256_private_key, root_certificate};

    #[derive(Default)]
    struct MockTransport<F> {
        requests: Mutex<Vec<TzapAuthHttpRequest>>,
        handler: F,
    }

    impl<F> MockTransport<F>
    where
        F: Fn(&TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> + Send + Sync,
    {
        fn new(handler: F) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                handler,
            }
        }
    }

    impl<F> TzapAuthHttpTransport for MockTransport<F>
    where
        F: Fn(&TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> + Send + Sync,
    {
        fn send(&self, request: &TzapAuthHttpRequest) -> Result<TzapAuthHttpResponse, TzapAuthError> {
            self.requests.lock().unwrap().push(request.clone());
            (self.handler)(request)
        }
    }

    #[test]
    fn test_fetch_on_miss_success() {
        let temp_dir = std::env::temp_dir().join(format!("tzap-online-resolver-{}", rand::random::<u64>()));
        let cache = TzapIntermediateCache::new(&temp_dir);

        let root_key = p256_private_key();
        let intermediate_key = p256_private_key();
        let root = root_certificate(&root_key);
        let intermediate = intermediate_certificate(&intermediate_key, root.as_ref(), root_key.as_ref(), root.as_ref());
        let intermediate_der = intermediate.to_der().unwrap();
        let intermediate_pem = intermediate.to_pem().unwrap();
        let intermediate_ski = zmanager_core::trust::extract_subject_key_identifier(&intermediate_der).unwrap();
        let intermediate_ski_b64 = URL_SAFE_NO_PAD.encode(&intermediate_ski);

        let summaries_json = serde_json::json!([
            {
                "certificateFingerprint": "sha256:abcd",
                "certificatePemUrl": "/v1/trust/intermediates/sha256:abcd/pem",
                "keyIdentifier": intermediate_ski_b64,
            }
        ]);
        let intermediate_pem_clone = intermediate_pem.clone();
        let mock_transport = MockTransport::new(move |request: &TzapAuthHttpRequest| {
            if request.url.ends_with("/v1/trust/intermediates") {
                Ok(TzapAuthHttpResponse {
                    status_code: 200,
                    body: serde_json::to_vec(&summaries_json).unwrap(),
                })
            } else if request.url.contains("/pem") {
                Ok(TzapAuthHttpResponse {
                    status_code: 200,
                    body: intermediate_pem_clone.clone(),
                })
            } else {
                Err(TzapAuthError::HttpStatus { status_code: 404 })
            }
        });

        let resolver = TzapOnlineIntermediateResolver::new(cache.clone(), Some("https://staging.tzap.org".to_owned()), mock_transport);

        // Resolve!
        let resolved_der = resolver.resolve_intermediate(&intermediate_ski).unwrap().expect("must resolve intermediate");
        assert_eq!(resolved_der, intermediate_der);

        // Verified cached on disk!
        let cached = cache.get_by_aki(&intermediate_ski).unwrap().expect("must now be in cache");
        assert_eq!(cached, intermediate_der);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_fetch_on_miss_offline_error() {
        let temp_dir = std::env::temp_dir().join(format!("tzap-online-resolver-offline-{}", rand::random::<u64>()));
        let cache = TzapIntermediateCache::new(&temp_dir);

        let mock_transport = MockTransport::new(|_: &TzapAuthHttpRequest| {
            Err(TzapAuthError::Transport { message: "Connection refused".to_owned() })
        });

        let resolver = TzapOnlineIntermediateResolver::new(cache, Some("https://staging.tzap.org".to_owned()), mock_transport);

        let aki = vec![1, 2, 3, 4];
        let err = resolver.resolve_intermediate(&aki).unwrap_err();
        match err {
            TzapIntermediateResolveError::OfflineMiss { issuer_key_identifier, reason } => {
                assert_eq!(issuer_key_identifier, URL_SAFE_NO_PAD.encode(&aki));
                assert!(reason.contains("Connection refused"));
            }
            other => panic!("expected OfflineMiss, got: {other:?}"),
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
