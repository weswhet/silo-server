//! Port of `internal/cache/replicas.go`: a best-effort census of live API replicas.

use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;

/// How long a presence marker outlives its last refresh: three refresh intervals, so one missed
/// refresh does not drop a live replica. `APIReplicaTTL`.
pub const REPLICA_TTL: Duration = Duration::from_secs(90);
/// How often a registered replica renews its marker. `apiReplicaRefreshInterval`.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const KEY_PREFIX: &str = "silo:api-replica:";

/// A best-effort census of live API replicas. Nothing routes on this count; a Redis failure only
/// silences the admin warning it feeds. `cache.APIReplicaPresence`.
pub struct ApiReplicaPresence {
    conn: MultiplexedConnection,
    id: String,
}

fn key(id: &str) -> String {
    format!("{KEY_PREFIX}{id}")
}

impl ApiReplicaPresence {
    /// A unique presence for this process, even when several replicas use the same logical node id.
    /// `NewAPIReplicaPresence`.
    pub fn new(conn: MultiplexedConnection, node_id: &str) -> Self {
        Self {
            conn,
            id: format!("{node_id}:{}", uuid::Uuid::new_v4()),
        }
    }

    async fn touch(&mut self) -> Result<(), redis::RedisError> {
        let now = silo_gocompat::time::GoTime::now_utc().rfc3339();
        self.conn
            .set_ex::<_, _, ()>(key(&self.id), now, REPLICA_TTL.as_secs())
            .await
    }

    /// Writes this replica's marker and spawns a task that renews it until `stop` resolves. `Register`.
    pub async fn register(
        mut self,
        mut stop: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<tokio::task::JoinHandle<()>, redis::RedisError> {
        self.touch().await?;
        Ok(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = &mut stop => {
                        let _ : Result<(), _> = self.conn.del(key(&self.id)).await;
                        return;
                    }
                    _ = ticker.tick() => {
                        let _ = self.touch().await;
                    }
                }
            }
        }))
    }

    /// How many API replicas currently hold a marker, including this one. `Count`.
    pub async fn count(conn: &mut MultiplexedConnection) -> Result<usize, redis::RedisError> {
        let mut cursor: u64 = 0;
        let mut count = 0usize;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{KEY_PREFIX}*"))
                .arg("COUNT")
                .arg(100)
                .query_async(conn)
                .await?;
            count += keys.len();
            if next == 0 {
                return Ok(count);
            }
            cursor = next;
        }
    }
}

/// `Count` with no presence at all reports one replica, matching Go's nil-receiver behavior.
pub async fn count_or_one(
    conn: Option<&mut MultiplexedConnection>,
) -> Result<usize, redis::RedisError> {
    match conn {
        Some(conn) => ApiReplicaPresence::count(conn).await,
        None => Ok(1),
    }
}
