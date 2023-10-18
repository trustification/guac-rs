use super::vulnerability::Vulnerability;

#[derive(Debug, Clone)]
pub struct CertifyVEXStatement {
    pub vulnerability: Vulnerability,
    pub status: VexStatus,
}

#[derive(Debug, Clone)]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}
