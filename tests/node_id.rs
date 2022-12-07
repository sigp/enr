use enr::*;

#[test]
fn test_eq_node_raw_node() {
    let node = NodeId::random();
    let raw = node.raw();
    assert_eq!(node, raw);
    assert_eq!(node.as_ref(), &raw[..]);
}

#[test]
fn test_node_display() {
    let node = NodeId::random();
    let hex_node = hex::encode(node.raw());
    let node_str = format!("0x{}..{}", &hex_node[0..4], &hex_node[hex_node.len() - 4..]);
    assert_eq!(node.to_string(), node_str);
}
