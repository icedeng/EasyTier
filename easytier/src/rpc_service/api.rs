use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;

use crate::{
    instance::instance::InstanceRpcServerHook,
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::ConfigRpcServer,
            instance::{
                AclManageRpcServer, ConnectorManageRpcServer, CredentialManageRpcServer,
                MappedListenerManageRpcServer, PeerManageRpcServer, PortForwardManageRpcServer,
                StatsRpcServer, TcpProxyRpcServer, VpnPortalRpcServer,
            },
            logger::LoggerRpcServer,
            manage::WebClientServiceServer,
        },
        peer_rpc::PeerCenterRpcServer,
        rpc_impl::{service_registry::ServiceRegistry, standalone::StandAloneServer},
        rpc_types::error::Error,
    },
    rpc_service::{
        acl_manage::AclManageRpcService, config::ConfigRpcService,
        connector_manage::ConnectorManageRpcService, credential_manage::CredentialManageRpcService,
        instance_manage::InstanceManageRpcService, logger::LoggerRpcService,
        mapped_listener_manage::MappedListenerManageRpcService,
        peer_center::PeerCenterManageRpcService, peer_manage::PeerManageRpcService,
        port_forward_manage::PortForwardManageRpcService, protected_port,
        proxy::TcpProxyRpcService, stats::StatsRpcService, vpn_portal::VpnPortalRpcService,
    },
    tunnel::{TunnelListener, tcp::TcpTunnelListener},
    web_client::{DefaultHooks, WebClientHooks},
};

pub struct ApiRpcServer<T: TunnelListener + 'static> {
    rpc_server: StandAloneServer<T>,
    protected_tcp_port: Option<u16>,
}

impl ApiRpcServer<TcpTunnelListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        rpc_access_token_file: Option<PathBuf>,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let rpc_access_token = load_rpc_access_token(rpc_access_token_file)?;
        let mut server = Self::from_tunnel_with_domain(
            TcpTunnelListener::new(
                format!("tcp://{}", rpc_addr)
                    .parse()
                    .context("failed to parse rpc portal address")?,
            ),
            instance_manager,
            rpc_access_token.as_deref().unwrap_or_default(),
        );
        protected_port::register_protected_tcp_port(rpc_addr.port());
        server.protected_tcp_port = Some(rpc_addr.port());

        server
            .rpc_server
            .set_hook(Arc::new(InstanceRpcServerHook::new(rpc_portal_whitelist)));

        Ok(server)
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self::from_tunnel_with_domain(tunnel, instance_manager, "")
    }

    pub fn from_tunnel_with_domain(
        tunnel: T,
        instance_manager: Arc<NetworkInstanceManager>,
        access_domain: &str,
    ) -> Self {
        let rpc_server = StandAloneServer::new(tunnel);
        register_api_rpc_service_with_domain(
            &instance_manager,
            rpc_server.registry(),
            None,
            access_domain,
        );
        Self {
            rpc_server,
            protected_tcp_port: None,
        }
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

impl<T: TunnelListener + 'static> Drop for ApiRpcServer<T> {
    fn drop(&mut self) {
        if let Some(port) = self.protected_tcp_port.take() {
            protected_port::unregister_protected_tcp_port(port);
        }
        self.rpc_server.registry().unregister_all();
    }
}

pub fn register_api_rpc_service(
    instance_manager: &Arc<NetworkInstanceManager>,
    registry: &ServiceRegistry,
    hooks: Option<Arc<dyn WebClientHooks>>,
) {
    if hooks
        .as_ref()
        .is_some_and(|hooks| !hooks.allows_remote_mutations())
    {
        registry.register(
            WebClientServiceServer::new(InstanceManageRpcService::new(
                instance_manager.clone(),
                hooks.expect("monitor-only hooks are present"),
            )),
            "",
        );
        return;
    }
    register_api_rpc_service_with_domain(instance_manager, registry, hooks, "");
}

fn register_api_rpc_service_with_domain(
    instance_manager: &Arc<NetworkInstanceManager>,
    registry: &ServiceRegistry,
    hooks: Option<Arc<dyn WebClientHooks>>,
    access_domain: &str,
) {
    registry.register(
        PeerManageRpcServer::new(PeerManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        ConnectorManageRpcServer::new(ConnectorManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        MappedListenerManageRpcServer::new(MappedListenerManageRpcService::new(
            instance_manager.clone(),
        )),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        VpnPortalRpcServer::new(VpnPortalRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    for client_type in ["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
        registry.register(
            TcpProxyRpcServer::new(TcpProxyRpcService::new(
                instance_manager.clone(),
                client_type,
            )),
            &rpc_domain(access_domain, client_type),
        );
    }

    registry.register(
        AclManageRpcServer::new(AclManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        PortForwardManageRpcServer::new(PortForwardManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        StatsRpcServer::new(StatsRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        LoggerRpcServer::new(LoggerRpcService),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        ConfigRpcServer::new(ConfigRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        WebClientServiceServer::new(InstanceManageRpcService::new(
            instance_manager.clone(),
            hooks.unwrap_or(Arc::new(DefaultHooks)),
        )),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        PeerCenterRpcServer::new(PeerCenterManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );

    registry.register(
        CredentialManageRpcServer::new(CredentialManageRpcService::new(instance_manager.clone())),
        &rpc_domain(access_domain, ""),
    );
}

fn rpc_domain(access_domain: &str, service_domain: &str) -> String {
    match (access_domain.is_empty(), service_domain.is_empty()) {
        (true, _) => service_domain.to_string(),
        (false, true) => access_domain.to_string(),
        (false, false) => format!("{access_domain}/{service_domain}"),
    }
}

fn load_rpc_access_token(path: Option<PathBuf>) -> anyhow::Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let token = std::fs::read_to_string(path)
        .context("failed to read rpc access token file")?
        .trim()
        .to_string();
    if token.len() < 32
        || token.len() > 128
        || !token
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
    {
        anyhow::bail!("rpc access token file contains an invalid token");
    }
    Ok(Some(token))
}

fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        Ok(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        let mut rpc_addr = rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?;
        select_proper_rpc_port(&mut rpc_addr)?;
        rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{
            api::manage::{
                CollectNetworkInfoRequest, WebClientService, WebClientServiceClientFactory,
            },
            rpc_impl::standalone::StandAloneClient,
            rpc_types::controller::BaseController,
        },
        tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener},
    };

    #[test]
    fn access_token_namespaces_all_rpc_domains() {
        assert_eq!(rpc_domain("token", ""), "token");
        assert_eq!(rpc_domain("token", "tcp"), "token/tcp");
        assert_eq!(rpc_domain("", "tcp"), "tcp");
    }

    #[test]
    fn rpc_access_token_file_rejects_short_token() {
        let path =
            std::env::temp_dir().join(format!("easytier-rpc-token-test-{}", std::process::id()));
        std::fs::write(&path, "short").unwrap();
        assert!(load_rpc_access_token(Some(path.clone())).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn access_token_rejects_default_domain_client() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url: url::Url = format!("tcp://127.0.0.1:{port}").parse().unwrap();
        let manager = Arc::new(NetworkInstanceManager::new());
        let _server = ApiRpcServer::from_tunnel_with_domain(
            TcpTunnelListener::new(url.clone()),
            manager,
            "private-domain-token",
        )
        .serve()
        .await
        .unwrap();

        let mut unauthorized = StandAloneClient::new(TcpTunnelConnector::new(url.clone()));
        let unauthorized_client = unauthorized
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(String::new())
            .await
            .unwrap();
        assert!(
            unauthorized_client
                .collect_network_info(
                    BaseController::default(),
                    CollectNetworkInfoRequest { inst_ids: vec![] },
                )
                .await
                .is_err()
        );

        let mut authorized = StandAloneClient::new(TcpTunnelConnector::new(url));
        let authorized_client = authorized
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(
                "private-domain-token".to_string(),
            )
            .await
            .unwrap();
        assert!(
            authorized_client
                .collect_network_info(
                    BaseController::default(),
                    CollectNetworkInfoRequest { inst_ids: vec![] },
                )
                .await
                .is_ok()
        );
    }
}
