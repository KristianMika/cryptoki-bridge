#[derive(Clone, Copy)]
pub(crate) enum ProtocolType {
    #[cfg(all(feature = "mocked_eddsa_communicator", test))]
    Ed25519,
    ElGamal,
    FROST,
    GG18,
}
