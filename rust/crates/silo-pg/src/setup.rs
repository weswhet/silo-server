//! Per-connection setup, Go's `prepareConnection`.

use tokio_postgres::{Client, SimpleQueryMessage};

/// The `jit` setting Silo runs with.
pub const JIT_OFF: &str = "off";

/// What a connection learned while it was set up.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VectorTypes {
    pub vector: Option<u32>,
    pub halfvec: Option<u32>,
}

/// Turns JIT off for the session unless something already chose it, then looks up the vector types.
pub(crate) async fn prepare_connection(
    client: &Client,
) -> Result<VectorTypes, tokio_postgres::Error> {
    disable_unconfigured_jit(client).await?;
    vector_types(client).await
}

async fn disable_unconfigured_jit(client: &Client) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "SELECT set_config('jit', $1, false) FROM pg_settings WHERE name = 'jit' AND source = 'default'",
            &[&JIT_OFF],
        )
        .await?;
    Ok(())
}

// A database without the extension yet, such as a new one before its first migration, has neither
// type. The codecs check the type by name, so they work once `Pool::reset` reconnects.
async fn vector_types(client: &Client) -> Result<VectorTypes, tokio_postgres::Error> {
    let messages = client
        .simple_query("SELECT to_regtype('vector')::oid, to_regtype('halfvec')::oid")
        .await?;
    for message in messages {
        if let SimpleQueryMessage::Row(row) = message {
            return Ok(VectorTypes {
                vector: row.get(0).and_then(|v| v.parse().ok()),
                halfvec: row.get(1).and_then(|v| v.parse().ok()),
            });
        }
    }
    Ok(VectorTypes::default())
}
