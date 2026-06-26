use std::path::PathBuf;

use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use porto::cli::Cli;
use porto::cli::ServerCtrl;
use porto::ctrl::CtrlMsg;
use porto::ctrl::SD_CTRL_SOCK_PATH;
use porto::ctrl::UNINSTALL_SCRIPT_URL;
use porto::ctrl::execute_remote_script;
use porto::ctrl::prompt_confirmation;
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
            if let Err(e) = send_ctrl_msg(CtrlMsg::Stop, SD_CTRL_SOCK_PATH).await {
                error!("{:#}", e);
                return Err(anyhow!(
                    "unable to send ctrl message, to shut down porto run: systemctl stop porto"
                ));
            };
            println!("shutdown signal sent! Check \"systemctl status porto\" for confirmation")
        }
        ServerCtrl::Status => {
            let res = send_ctrl_msg(CtrlMsg::Status, SD_CTRL_SOCK_PATH).await;
            if res.is_ok() {
                println!("server is running!")
            } else {
                return Err(anyhow!("server failed to respond"));
            }
        }
        ServerCtrl::Remove => {
            let prompt ="do you wish to remove porto? y/n";
            prompt_confirmation(prompt);

            execute_remote_script(UNINSTALL_SCRIPT_URL).await?;

            println!("uninstall successful!")
        }
        ServerCtrl::Config(args) => {
            let path: PathBuf = [CONFIG_FOLDER, CONFIG_FILENAME].iter().collect();
            if args.init {
                println!("fetching config...");
                write_tmpl_config(&path).await?;
            }
            open_config_editor(&path)?;
        }
    }
    Ok(())
}
