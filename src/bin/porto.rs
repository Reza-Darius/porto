use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use porto::cli::Cli;
use porto::cli::ServerCtrl;
use porto::ctrl::CtrlMsg;
use porto::ctrl::execute_remote_bash;
use porto::ctrl::send_ctrl_msg;
use porto::server::run;
use porto::setup::setup_tracing;
use tikv_jemallocator::Jemalloc;

use porto::config::*;
use tracing::error;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_tracing();

    match cli.command {
        ServerCtrl::Start(run_args) => {
            let config = setup_config(Some(&run_args))?;
            run(&config).await?;
        }
        ServerCtrl::Stop => {
            if let Err(e) = send_ctrl_msg(CtrlMsg::Stop).await {
                error!("{:#}", e);
                return Err(anyhow!(
                    "unable to send ctrl message, to shut down porto run: systemctl stop porto"
                ));
            };
            println!("shutdown signal sent! Check \"systemctl status porto\" for confirmation")
        }
        ServerCtrl::Status => {
            let res = send_ctrl_msg(CtrlMsg::Status).await;
            if res.is_ok() {
                println!("server is running!")
            }
        }
        ServerCtrl::Remove => {
            let url = "https://raw.githubusercontent.com/Reza-Darius/porto/main/scripts/uninstall.sh";
            execute_remote_bash(url).await?;

            println!("uninstall successful!")
        }
    }
    Ok(())
}
