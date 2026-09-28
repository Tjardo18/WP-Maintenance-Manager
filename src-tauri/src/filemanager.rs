use crate::{database::Database, error::AppError};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilemanagerContext {
    pub site_id: String,
    pub site_name: String,
    pub site_url: String,
}

// Metadata only: this context is not authorization to access remote files.
pub fn context(database: &Database, site_id: &str) -> Result<FilemanagerContext, AppError> {
    let stored = database.get_site(site_id)?;
    Ok(FilemanagerContext {
        site_id: stored.site.id,
        site_name: stored.site.name,
        site_url: stored.site.url,
    })
}
