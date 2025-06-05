use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};

use crate::utils::{
    NetworkActivityAction, NetworkActivityLogData, NetworkActivityLogger, NetworkActivityType,
};

pub struct NActPostgresLogger {
    runtime: Runtime,
    client: Arc<Mutex<Client>>,
}

impl NetworkActivityType {
    fn to_string(&self) -> &str {
        match &self {
            NetworkActivityType::TcpSni => "tcp_sni",
            NetworkActivityType::TcpSniOverwrite => "tcp_sni_overwrite",
            NetworkActivityType::None => "none",
        }
    }
}

impl NetworkActivityAction {
    fn to_string(&self) -> &str {
        match &self {
            NetworkActivityAction::Accept => "accept",
            NetworkActivityAction::Drop => "drop",
        }
    }
}

impl NActPostgresLogger {
    pub fn new(config: &str) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let config = String::from(config);

        let (client, connection) =
            runtime.block_on(tokio_postgres::connect(config.as_ref(), NoTls))?;

        // The connection object performs the actual communication with the database,
        // so spawn it off to run on its own.
        runtime.spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {e}");
            }
        });

        Ok(NActPostgresLogger {
            runtime,
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub fn init_database_tables(&self) -> Result<()> {
        let client = Arc::clone(&self.client);

        let handle = self.runtime.spawn(async move {
            client
                .lock()
                .await
                .batch_execute(
                    format!(
                        r#"
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nact_type') THEN
                        CREATE TYPE nact_type AS ENUM (
                            '{}','{}','{}'
                        );
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'nact_action') THEN
                        CREATE TYPE nact_action AS ENUM (
                            '{}','{}'
                        );
                    END IF;
                    CREATE TABLE IF NOT EXISTS network_activity (
                        timestamp timestamp NOT NULL DEFAULT current_timestamp,
                        saddr inet NOT NULL,
                        daddr inet NOT NULL,
                        sport integer NOT NULL,
                        dport integer NOT NULL,
                        sni_name varchar(200),
                        atype nact_type NOT NULL,
                        action nact_action NOT NULL
                    );
                END$$;
            "#,
                        NetworkActivityType::TcpSni.to_string(),
                        NetworkActivityType::TcpSniOverwrite.to_string(),
                        NetworkActivityType::None.to_string(),
                        NetworkActivityAction::Accept.to_string(),
                        NetworkActivityAction::Drop.to_string(),
                    )
                    .as_str(),
                )
                .await
        });

        let res = self.runtime.block_on(handle).unwrap();

        res.context("Init Postgresql tables")
    }
}

impl NetworkActivityLogger for NActPostgresLogger {
    fn post(&self, data: &NetworkActivityLogData) -> Result<()> {
        let cln = Arc::clone(&self.client);
        let data = data.clone();

        let future = async move {
            let res = cln
                .lock()
                .await
                .execute(
                    format!(
                        r#"
                INSERT INTO network_activity(
                    saddr, 
                    daddr,
                    sport,
                    dport,
                    sni_name,
                    atype,
                    action
                ) VALUES ($1, $2, $3, $4, $5, '{}', '{}')
            "#,
                        data.atype.to_string(),
                        data.action.to_string()
                    )
                    .as_ref() as &str,
                    &[
                        &data.saddr,
                        &data.daddr,
                        &(data.sport as i32),
                        &(data.dport as i32),
                        &data.sni_name,
                    ],
                )
                .await;

            if let Err(err) = res {
                eprintln!("Failed to log {data:?}: {err}");
            }
        };

        let _handle = self.runtime.spawn(future);

        Ok(())
    }
}
