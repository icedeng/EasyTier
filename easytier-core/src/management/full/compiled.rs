use std::sync::Arc;

use easytier_proto::{
    api::{
        config::ConfigRpcServer,
        instance::{
            AclManageRpcServer, ConnectorManageRpcServer, CredentialManageRpcServer,
            MappedListenerManageRpcServer, PeerManageRpcServer, PortForwardManageRpcServer,
            StatsRpcServer, VpnPortalRpcServer,
        },
    },
    peer_rpc::PeerCenterRpcServer,
};

use super::super::instance_rpc::InstanceManagementRpc;
use super::ConfigFileStorage;
use crate::{
    instance::{
        CoreInstance, CoreInstanceHost,
        manager::{InstanceFactory, InstanceManager},
    },
    rpc::service_registry::ServiceRegistry,
};

/// Registers each Instance-targeted management protocol Interface once for
/// the complete process-level Instance collection.
pub fn register_instance_management_rpc<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
    storage: Arc<dyn ConfigFileStorage>,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    register_instance_management_rpc_with_domain(manager, registry, storage, "");
}

pub fn register_instance_management_rpc_with_domain<F, H>(
    manager: Arc<InstanceManager<F>>,
    registry: &ServiceRegistry,
    storage: Arc<dyn ConfigFileStorage>,
    domain: &str,
) where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    let rpc = InstanceManagementRpc::<F>::new_with_config_storage(manager.clone(), storage);
    registry.register(PeerManageRpcServer::new(rpc.clone()), domain);
    registry.register(ConnectorManageRpcServer::new(rpc.clone()), domain);
    registry.register(MappedListenerManageRpcServer::new(rpc.clone()), domain);
    registry.register(VpnPortalRpcServer::new(rpc.clone()), domain);
    super::packet_proxy::register_with_domain(manager.clone(), registry, domain);
    registry.register(AclManageRpcServer::new(rpc.clone()), domain);
    registry.register(PortForwardManageRpcServer::new(rpc.clone()), domain);
    registry.register(StatsRpcServer::new(rpc.clone()), domain);
    registry.register(ConfigRpcServer::new(rpc.clone()), domain);
    registry.register(CredentialManageRpcServer::new(rpc.clone()), domain);
    registry.register(PeerCenterRpcServer::new(rpc), domain);
}
