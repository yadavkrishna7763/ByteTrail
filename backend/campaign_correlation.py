import networkx as nx
from typing import Dict, List


def build_campaign_attribution_graph(emails_list: List[Dict]) -> Dict:
    """
    Construct a Threat Infrastructure & Campaign Attribution Network Graph
    connecting emails to originating IPs, Domains, and Threat Actor Clusters.
    """
    G = nx.Graph()
    nodes = []
    edges = []

    domains_seen = {}
    ips_seen = {}
    actors_seen = {}

    for email in emails_list:
        email_id = f"CASE #{email['id']}"
        risk = (email.get("risk_level") or "low").lower()
        sender = email.get("sender", "unknown")
        ip = email.get("ip_address") or "Unknown IP"
        country = email.get("country") or "Unknown"

        domain = sender.split("@")[-1].strip(">").lower() if "@" in sender else "unknown-domain"

        # Email node
        nodes.append({
            "id": email_id,
            "label": email_id,
            "sub": email.get("subject", "")[:28],
            "type": "email",
            "risk": risk,
            "score": email.get("final_score", 0),
        })

        # Domain node
        domain_node_id = f"DOMAIN:{domain}"
        if domain_node_id not in domains_seen:
            domains_seen[domain_node_id] = True
            nodes.append({
                "id": domain_node_id,
                "label": domain,
                "type": "domain",
                "risk": risk,
            })
        edges.append({
            "source": email_id,
            "target": domain_node_id,
            "relation": "SENT_VIA",
        })

        # IP / Geo node
        if ip and ip != "No IP":
            ip_node_id = f"IP:{ip}"
            if ip_node_id not in ips_seen:
                ips_seen[ip_node_id] = True
                nodes.append({
                    "id": ip_node_id,
                    "label": f"{ip} ({country})",
                    "type": "ip",
                    "risk": risk,
                })
            edges.append({
                "source": email_id,
                "target": ip_node_id,
                "relation": "RELAY_ORIGIN",
            })

            # Connect Domain to IP
            edges.append({
                "source": domain_node_id,
                "target": ip_node_id,
                "relation": "HOSTED_ON",
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }
