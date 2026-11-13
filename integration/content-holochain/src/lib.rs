//! Read-only [`MetadataSource`] over a trusted local Holochain conductor.
//!
//! Reads the **existing** Music S2 storage DNA (`music_storage` zome,
//! holochain-music `dna/` at bd7aabc) through an authenticated app WebSocket
//! with signed zome calls, the same way Music's `music_conductor_bridge`
//! does. No DNA, entry type or zome function is added or changed.
//!
//! Trust model:
//! * the admin WebSocket must be loopback (a privileged local interface);
//! * the installed app's storage cell must have the caller-pinned DNA hash;
//! * every record's `author` is the coordinator zome's
//!   `record.action().author()` for a validated record, not a body field;
//! * signing credentials only authorise this client's zome calls; no artist,
//!   host or content key is involved.
//!
//! Connection or call failures surface as [`MetadataError`] (availability),
//! never as a binding/authorisation denial.

#![forbid(unsafe_code)]

use holo_hash::{ActionHash, AgentPubKey};
use holochain_client::{
    AdminWebsocket, AllowedOrigins, AppWebsocket, AuthorizeSigningCredentialsPayload, CellInfo,
    ClientAgentSigner, DynAgentSigner, ExternIO, ZomeCallTarget,
};
use holochain_content_core::binding::ConductorRecord;
use holochain_content_core::PackageId;
use holochain_content_retrieval::{MetadataError, MetadataSource};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;

/// Allowed origin used for the app interface this client attaches.
pub const ORIGIN: &str = "holochain-media-core-reader";
/// Music S2 coordinator zome name.
pub const STORAGE_ZOME: &str = "music_storage";
/// Upper bound on records accepted from one zome call.
pub const MAX_RECORDS_PER_CALL: usize = 1024;

#[derive(Debug, Deserialize)]
struct WireRecord {
    author: String,
    action_hash: ActionHash,
    body: Value,
}

#[derive(Debug, Serialize)]
struct FileLookup {
    owner_agent: String,
    file_id: String,
}

fn unavailable(context: &str, error: impl std::fmt::Display) -> MetadataError {
    MetadataError(format!("{context}: {error}"))
}

fn agent(text: &str) -> Result<AgentPubKey, MetadataError> {
    AgentPubKey::try_from(text).map_err(|e| unavailable("invalid agent identifier", e))
}

/// Which installed app and cell to read.
#[derive(Clone, Debug)]
pub struct ConductorTarget {
    /// Loopback admin WebSocket of the reader's own conductor.
    pub admin: SocketAddr,
    /// Installed app ID.
    pub app_id: String,
    /// Role name of the Music storage DNA in that app.
    pub storage_role: String,
    /// Expected storage DNA hash (`uhC0k…`), pinned independently.
    pub expected_storage_dna: String,
}

/// An authenticated, read-only connection to the storage cell.
pub struct ConductorResolver {
    app: AppWebsocket,
    role: String,
    reader_agent: String,
}

impl ConductorResolver {
    /// Connect, check the app/role/DNA pin and open a signed app socket.
    pub async fn connect(target: &ConductorTarget) -> Result<Self, MetadataError> {
        if !target.admin.ip().is_loopback() || target.admin.port() == 0 {
            return Err(MetadataError(
                "admin WebSocket must be a loopback address".into(),
            ));
        }
        let admin = AdminWebsocket::connect(target.admin, Some(ORIGIN.into()))
            .await
            .map_err(|e| unavailable("admin websocket", e))?;
        let installed = admin
            .list_apps(None)
            .await
            .map_err(|e| unavailable("list apps", e))?
            .into_iter()
            .find(|a| a.installed_app_id == target.app_id)
            .ok_or_else(|| MetadataError("app is not installed on this conductor".into()))?;
        let cells = installed
            .cell_info
            .get(&target.storage_role)
            .ok_or_else(|| MetadataError("storage role not present".into()))?;
        let mut provisioned = cells.iter().filter_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        });
        let cell = provisioned
            .next()
            .ok_or_else(|| MetadataError("no provisioned storage cell".into()))?;
        if provisioned.next().is_some() {
            return Err(MetadataError("ambiguous provisioned storage cells".into()));
        }
        if cell.dna_hash().to_string() != target.expected_storage_dna {
            return Err(MetadataError(
                "installed storage DNA hash does not match the trusted pin".into(),
            ));
        }
        let signer = ClientAgentSigner::default();
        let credentials = admin
            .authorize_signing_credentials(AuthorizeSigningCredentialsPayload {
                cell_id: cell.clone(),
                functions: None,
            })
            .await
            .map_err(|e| unavailable("authorize signing credentials", e))?;
        signer.add_credentials(cell.clone(), credentials);
        let app_port = admin
            .attach_app_interface(
                0,
                None,
                AllowedOrigins::from(ORIGIN.to_string()),
                Some(target.app_id.clone()),
            )
            .await
            .map_err(|e| unavailable("attach app interface", e))?;
        let token = admin
            .issue_app_auth_token(target.app_id.clone().into())
            .await
            .map_err(|e| unavailable("issue app token", e))?
            .token;
        let dyn_signer: DynAgentSigner = signer.into();
        let app = AppWebsocket::connect(
            (std::net::Ipv4Addr::LOCALHOST, app_port),
            token,
            dyn_signer,
            Some(ORIGIN.into()),
        )
        .await
        .map_err(|e| unavailable("app websocket", e))?;
        if &app.my_pub_key != cell.agent_pubkey() {
            return Err(MetadataError(
                "app socket agent differs from the storage cell agent".into(),
            ));
        }
        Ok(Self {
            reader_agent: cell.agent_pubkey().to_string(),
            app,
            role: target.storage_role.clone(),
        })
    }

    /// The reader's own Holochain agent (from the conductor, not the caller).
    pub fn reader_agent(&self) -> &str {
        &self.reader_agent
    }

    async fn call<I: Serialize + std::fmt::Debug, O: DeserializeOwned + std::fmt::Debug>(
        &self,
        function: &str,
        input: &I,
    ) -> Result<O, MetadataError> {
        let payload = ExternIO::encode(input).map_err(|e| unavailable("encode", e))?;
        let output = self
            .app
            .call_zome(
                ZomeCallTarget::RoleName(self.role.clone()),
                STORAGE_ZOME.into(),
                function.into(),
                payload,
            )
            .await
            .map_err(|e| unavailable(function, e))?;
        output.decode().map_err(|e| unavailable(function, e))
    }

    async fn records<I: Serialize + std::fmt::Debug>(
        &self,
        function: &str,
        input: &I,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        let rows: Vec<WireRecord> = self.call(function, input).await?;
        if rows.len() > MAX_RECORDS_PER_CALL {
            return Err(MetadataError(format!("{function}: too many records")));
        }
        // A malformed row is skipped rather than trusted; selection later
        // fails closed if the required record is then missing.
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                ConductorRecord::from_validated_conductor(
                    r.author,
                    r.action_hash.to_string(),
                    r.body,
                )
                .ok()
            })
            .collect())
    }
}

impl MetadataSource for ConductorResolver {
    async fn signing_keys(&mut self, agent_id: &str) -> Result<Vec<ConductorRecord>, MetadataError> {
        let key = agent(agent_id)?;
        self.records("get_signing_keys", &key).await
    }

    async fn file_commitments(
        &mut self,
        agent_id: &str,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        let key = agent(agent_id)?;
        self.records("get_file_commitments", &key).await
    }

    async fn replica_claims(
        &mut self,
        owner_agent: &str,
        package: PackageId,
    ) -> Result<Vec<ConductorRecord>, MetadataError> {
        agent(owner_agent)?;
        self.records(
            "get_replica_claims",
            &FileLookup {
                owner_agent: owner_agent.to_owned(),
                file_id: package.to_string(),
            },
        )
        .await
    }

    async fn moq_endpoints(&mut self, host: &str) -> Result<Vec<ConductorRecord>, MetadataError> {
        let key = agent(host)?;
        self.records("get_moq_endpoints", &key).await
    }
}
