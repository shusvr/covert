use anyhow::{Context, Result};
use covert::config::Config;
use futures::StreamExt;
use rtnetlink::{
    Handle, RouteDelRequest, RouteMessageBuilder, RuleDelRequest,
    packet_route::{
        route::{RouteAddress, RouteAttribute, RouteHeader},
        rule::{RuleAction, RuleAttribute, RuleFlags},
    },
};
use std::{
    hash::{DefaultHasher, Hasher},
    net::{IpAddr, Ipv4Addr},
};
use tokio::task::JoinSet;
use tracing::{debug, error};

#[derive(Default)]
pub(super) struct TableCleanup {
    rules: Vec<RuleDelRequest>,
    routes: Vec<RouteDelRequest>,
}

impl TableCleanup {
    pub(super) async fn execute(self) -> Result<()> {
        let mut first_error = None;
        for request in self.rules.into_iter().rev() {
            if let Err(err) = request
                .execute()
                .await
                .context("failed to remove routing rule")
            {
                error!("{err:#}");
                first_error.get_or_insert(err);
            }
        }
        for request in self.routes.into_iter().rev() {
            if let Err(err) = request.execute().await.context("failed to remove route") {
                error!("{err:#}");
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub(super) async fn setup_table(
    handle: &Handle,
    config: &Config,
    ifidx: u32,
    cleanup: &mut TableCleanup,
) -> Result<()> {
    let mut h = DefaultHasher::new();
    h.write(config.dev_name.as_bytes());
    let table_id = h.finish() as u32;

    for peer in config.peers.iter() {
        for route in peer.allowed_ips.iter() {
            debug!("Adding route for {route}");

            let msg = RouteMessageBuilder::<IpAddr>::new()
                .priority(peer.metric as _)
                .output_interface(ifidx)
                .destination_prefix(route.addr(), route.prefix_len())?
                .table_id(table_id)
                .build();
            handle
                .route()
                .add(msg.clone())
                .execute()
                .await
                .context("failed to add route")?;
            cleanup.routes.push(handle.route().del(msg));
        }
    }

    const MAIN_RULE_PRIORITY: u32 = u16::MAX as u32 / 4;

    let mut main_rule = handle
        .rule()
        .add()
        .v4()
        .priority(MAIN_RULE_PRIORITY)
        .table_id(u32::from(RouteHeader::RT_TABLE_MAIN))
        .action(RuleAction::ToTable);
    main_rule
        .message_mut()
        .attributes
        .push(RuleAttribute::SuppressPrefixLen(0));
    let del = handle.rule().del(main_rule.message_mut().clone());
    main_rule.execute().await?;
    cleanup.rules.push(del);

    let mut tunnel_rule = handle
        .rule()
        .add()
        .v4()
        .priority(MAIN_RULE_PRIORITY + 1)
        .fw_mark(config.interface.fwmark)
        .table_id(table_id)
        .action(RuleAction::ToTable);
    tunnel_rule.message_mut().header.flags |= RuleFlags::Invert;
    let del = handle.rule().del(tunnel_rule.message_mut().clone());
    tunnel_rule.execute().await?;
    cleanup.rules.push(del);

    Ok(())
}

pub(super) async fn get_public_ip() -> Result<Option<Ipv4Addr>> {
    let (conn, handle, _recv) = rtnetlink::new_connection()?;
    let mut set = JoinSet::new();
    set.spawn(conn);

    let Some(item) = handle
        .route()
        .get(
            RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::from_octets([1; 4]), 32)
                .build(),
        )
        .execute()
        .next()
        .await
        .transpose()?
    else {
        return Ok(None);
    };

    match item.attributes.iter().find_map(|attr| match attr {
        RouteAttribute::PrefSource(RouteAddress::Inet(addr)) => Some(addr),
        _ => None,
    }) {
        Some(x) if is_global(x) => Ok(Some(*x)),
        _ => Ok(None),
    }
}

fn is_global(x: &Ipv4Addr) -> bool {
    !(x.octets()[0] == 0 // "This network"
        || x.is_private()
        || (x.octets()[0] == 100 && (x.octets()[1] & 0b1100_0000 == 0b0100_0000))
        || x.is_loopback()
        || x.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        // .9 and .10 are documented as globally reachable so they're excluded
        || (
            x.octets()[0] == 192 && x.octets()[1] == 0 && x.octets()[2] == 0
            && x.octets()[3] != 9 && x.octets()[3] != 10
        )
        // 6a44-relay anycast address (`192.88.99.2/32`)
        || matches!(x.octets(), [192, 88, 99, 2])
        || x.is_documentation()
        || (x.octets()[0] == 198 && (x.octets()[1] & 0xfe) == 18)
        || (x.octets()[0] & 240 == 240 && !x.is_broadcast())
        || x.is_broadcast())
}
