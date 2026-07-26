use codewire_core::{ByteChunk, CoreError, HttpClient, HttpResponse};

/// HTTP client backed by `reqwest::Client`
#[derive(Clone)]
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, CoreError> {
        let mut builder = self.client.get(url);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = builder.send().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }

    async fn post_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, CoreError> {
        let mut builder = self.client.post(url).body(body.to_vec());
        builder = builder.header("Content-Type", "application/json");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = builder.send().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let resp_body = resp.bytes().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        Ok(HttpResponse {
            status,
            body: resp_body.to_vec(),
        })
    }

    async fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        form_data: &[(&str, &str)],
    ) -> Result<HttpResponse, CoreError> {
        let mut builder = self.client.post(url).form(form_data);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = builder.send().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }

    async fn post_streaming(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, tokio::sync::mpsc::Receiver<ByteChunk>), CoreError> {
        use futures::StreamExt;

        let mut builder = self.client.post(url).body(body.to_vec());
        builder = builder.header("Content-Type", "application/json");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = builder.send().await.map_err(|e| CoreError::Network {
            message: e.to_string(),
        })?;
        let status = resp.status().as_u16();
        let (tx, rx) = tokio::sync::mpsc::channel::<ByteChunk>(32);

        let mut stream = resp.bytes_stream();
        tokio::spawn(async move {
            while let Some(chunk) = stream.next().await {
                let result = match chunk {
                    Ok(bytes) => Ok(bytes.to_vec()),
                    Err(e) => Err(CoreError::Network {
                        message: e.to_string(),
                    }),
                };
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        });

        Ok((status, rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_get_request() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
            .mount(&mock_server)
            .await;

        let client = ReqwestHttpClient::new();
        let resp = client
            .get(
                &format!("{}/test", mock_server.uri()),
                &[("Accept", "application/json")],
            )
            .await
            .unwrap();

        assert!(resp.is_success());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text(), r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn test_post_json() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"id":"123"}"#))
            .mount(&mock_server)
            .await;

        let client = ReqwestHttpClient::new();
        let body = r#"{"name":"test"}"#;
        let resp = client
            .post_json(&format!("{}/api", mock_server.uri()), &[], body.as_bytes())
            .await
            .unwrap();

        assert_eq!(resp.status, 201);
        assert_eq!(resp.text(), r#"{"id":"123"}"#);
    }

    #[tokio::test]
    async fn test_post_form() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/form"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock_server)
            .await;

        let client = ReqwestHttpClient::new();
        let resp = client
            .post_form(
                &format!("{}/form", mock_server.uri()),
                &[],
                &[("key", "value")],
            )
            .await
            .unwrap();

        assert!(resp.is_success());
    }

    #[tokio::test]
    async fn test_post_streaming() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/stream"))
            .respond_with(ResponseTemplate::new(200).set_body_string("chunk1chunk2chunk3"))
            .mount(&mock_server)
            .await;

        let client = ReqwestHttpClient::new();
        let (status, mut rx) = client
            .post_streaming(&format!("{}/stream", mock_server.uri()), &[], b"{}")
            .await
            .unwrap();

        assert_eq!(status, 200);

        let mut all_data = Vec::new();
        while let Some(chunk) = rx.recv().await {
            all_data.extend(chunk.unwrap());
        }
        assert_eq!(String::from_utf8(all_data).unwrap(), "chunk1chunk2chunk3");
    }

    #[tokio::test]
    async fn test_get_error_status() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = ReqwestHttpClient::new();
        let resp = client
            .get(&format!("{}/not-found", mock_server.uri()), &[])
            .await
            .unwrap();

        assert!(!resp.is_success());
        assert_eq!(resp.status, 404);
    }
}
