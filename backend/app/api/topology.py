from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.app.core.database import get_db
from backend.app.models.host import Host, Port
from backend.app.models.user import User
from backend.app.schemas.common import TopologyResponse, TopologyNode, TopologyEdge
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/topology", tags=["Topology"])

@router.get("", response_model=TopologyResponse)
def get_network_topology(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Host)
    if scan_id:
        query = query.filter(Host.scan_id == scan_id)
    hosts = query.all()

    nodes: List[TopologyNode] = []
    edges: List[TopologyEdge] = []

    # Gateway node anchor
    gateway_id = "node-gateway-0"
    nodes.append(TopologyNode(
        id=gateway_id,
        label="Subnet Gateway / Switch",
        type="gateway",
        ip="192.168.1.1 (Gateway)",
        risk_score=5.0,
        risk_level="LOW",
        open_ports_count=0,
        os="Network Appliance"
    ))

    for host in hosts:
        h_id = f"host-{host.id}"
        open_ports = len(host.ports)
        nodes.append(TopologyNode(
            id=h_id,
            label=host.hostname or host.ip_address,
            type="host",
            ip=host.ip_address,
            risk_score=host.risk_score,
            risk_level=host.risk_level,
            open_ports_count=open_ports,
            os=host.os_name
        ))

        # Edge from gateway to host
        edges.append(TopologyEdge(
            source=gateway_id,
            target=h_id,
            relationship="SUBNET_MEMBER",
            inferred=False
        ))

        # Services as child nodes
        for port in host.ports:
            p_id = f"svc-{port.id}"
            nodes.append(TopologyNode(
                id=p_id,
                label=f"{port.service_name} ({port.port_number}/{port.protocol})",
                type="service",
                ip=f"{host.ip_address}:{port.port_number}",
                risk_score=host.risk_score,
                risk_level=host.risk_level,
                open_ports_count=1,
                os="Service"
            ))
            edges.append(TopologyEdge(
                source=h_id,
                target=p_id,
                relationship="HOSTS_SERVICE",
                inferred=False
            ))

    return TopologyResponse(nodes=nodes, edges=edges)
