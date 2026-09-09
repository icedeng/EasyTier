use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;
#[cfg(feature = "management")]
use easytier_core::management::ManagementServer;
use easytier_core::{management::ReadOnlyManagementServer, socket::SocketListener, tunnel::Tunnel};

#[cfg(feature = "management")]
use crate::{
    instance::config_storage::NativeConfigFileStorage, rpc_service::logger::NativeLoggerControl,
    web_client::DefaultHooks,
};
use crate::{
    instance::factory::NativeInstanceManager,
    proto::{
        rpc::standalone::{RuntimeRpcListener, runtime_rpc_listener},
        rpc_types::error::Error,
    },
};

#[cfg(feature = "management")]
pub struct ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    rpc_server: ManagementServer<T>,
}

#[cfg(feature = "management")]
impl ApiRpcServer<RuntimeRpcListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        rpc_access_token_file: Option<PathBuf>,
        instance_manager: Arc<NativeInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let token = load_rpc_access_token(rpc_access_token_file)?;
        let mut server = Self::from_tunnel_with_domain(
            runtime_rpc_listener(rpc_addr),
            instance_manager,
            token.as_deref().unwrap_or_default(),
        );
        server.rpc_server.set_whitelist(rpc_portal_whitelist);

        Ok(server)
    }
}

#[cfg(feature = "management")]
impl<T> ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NativeInstanceManager>) -> Self {
        Self::from_tunnel_with_domain(tunnel, instance_manager, "")
    }

    pub fn from_tunnel_with_domain(
        tunnel: T,
        instance_manager: Arc<NativeInstanceManager>,
        access_domain: &str,
    ) -> Self {
        let rpc_server = ManagementServer::new_with_domain(
            tunnel,
            instance_manager,
            Arc::new(DefaultHooks),
            Arc::new(NativeConfigFileStorage),
            Arc::new(NativeLoggerControl),
            access_domain,
        );
        Self { rpc_server }
    }
}

fn load_rpc_access_token(path: Option<PathBuf>) -> anyhow::Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .context("failed to read rpc access token file")?
        .trim()
        .to_owned();
    if token.len() < 32
        || token.len() > 128
        || !token
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_'))
    {
        anyhow::bail!("rpc access token file contains an invalid token");
    }
    Ok(Some(token))
}

#[cfg(feature = "management")]
impl<T> ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

pub struct ReadOnlyApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    rpc_server: ReadOnlyManagementServer<T>,
}

impl ReadOnlyApiRpcServer<RuntimeRpcListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NativeInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(runtime_rpc_listener(rpc_addr), instance_manager);
        server.rpc_server.set_whitelist(rpc_portal_whitelist);
        Ok(server)
    }
}

impl<T> ReadOnlyApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NativeInstanceManager>) -> Self {
        Self {
            rpc_server: ReadOnlyManagementServer::new(tunnel, instance_manager),
        }
    }

    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    let mut rpc_addr = if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        Some(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?
    };
    select_proper_rpc_port(&mut rpc_addr)?;
    rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))
}

fn select_proper_rpc_port(addr: &mut Option<SocketAddr>) -> anyhow::Result<()> {
    match addr {
        None => {
            *addr = Some(SocketAddr::from(([0, 0, 0, 0], 0)));
            select_proper_rpc_port(addr)?;
            Ok(())
        }
        Some(addr) => {
            if addr.port() == 0 {
                let Some(port) = crate::utils::find_free_tcp_port(15888..15900) else {
                    tracing::warn!(
                        "No free port found for RPC portal, skipping setting RPC portal"
                    );
                    return Err(anyhow::anyhow!("No free port found for RPC portal"));
                };
                addr.set_port(port);
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "management"))]
mod tests {
    use std::{fmt, sync::Arc, time::Duration};

    use easytier_core::{
        rpc::bidirect::BidirectRpcManager,
        socket::SocketListener,
        tunnel::{Tunnel, ring::create_ring_tunnel_pair},
    };
    use tokio::sync::mpsc;

    use crate::{
        instance::factory::native_instance_manager,
        proto::{
            api::logger::{GetLoggerConfigRequest, LoggerRpc, LoggerRpcClientFactory},
            rpc_types::controller::BaseController,
        },
    };

    use super::{ApiRpcServer, load_rpc_access_token, parse_rpc_portal};

    #[test]
    fn zero_rpc_portal_is_resolved_before_listener_binding() {
        assert_ne!(parse_rpc_portal(Some("0".to_owned())).unwrap().port(), 0);
    }

    #[test]
    fn rpc_access_token_file_requires_a_valid_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");

        std::fs::write(&path, "a_valid_token_with_32_characters_1234\n").unwrap();
        assert_eq!(
            load_rpc_access_token(Some(path.clone()))
                .unwrap()
                .as_deref(),
            Some("a_valid_token_with_32_characters_1234")
        );

        std::fs::write(&path, "too-short\n").unwrap();
        assert!(load_rpc_access_token(Some(path.clone())).is_err());

        std::fs::write(&path, "invalid token with spaces and punctuation 123456").unwrap();
        assert!(load_rpc_access_token(Some(path)).is_err());
    }

    struct RingListener {
        accepted: mpsc::Receiver<Box<dyn Tunnel>>,
    }

    impl fmt::Debug for RingListener {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("RingListener").finish()
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for RingListener {
        type Accepted = Box<dyn Tunnel>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            self.accepted
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("ring test listener closed"))
        }

        fn local_url(&self) -> url::Url {
            "ring://management-test".parse().unwrap()
        }
    }

    #[tokio::test]
    async fn trusted_ring_management_transport_does_not_require_an_ip_host() {
        let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
        let (accepted, receiver) = mpsc::channel(1);
        accepted.send(server_tunnel).await.unwrap();
        let server = ApiRpcServer::from_tunnel(
            RingListener { accepted: receiver },
            Arc::new(native_instance_manager()),
        )
        .with_rx_timeout(Some(Duration::from_secs(1)))
        .serve()
        .await
        .unwrap();
        let client = BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(1)));
        client.run_with_tunnel(client_tunnel);
        let logger = client
            .rpc_client()
            .scoped_client::<LoggerRpcClientFactory<BaseController>>(1, 1, String::new());

        tokio::time::timeout(
            Duration::from_secs(1),
            logger.get_logger_config(BaseController::default(), GetLoggerConfigRequest::default()),
        )
        .await
        .unwrap()
        .unwrap();

        drop(server);
    }
}
