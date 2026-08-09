pub fn assert_dependency_contract() {
    assert_eq!(
        m2_rust_contract::transform("alpha"),
        "ALPHA",
        "M2_RUST_BREAKING_API_V2"
    );
    assert_eq!(m2_rust_noise::marker(), "stable");
}

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_contract_remains_compatible() {
        super::assert_dependency_contract();
    }
}
