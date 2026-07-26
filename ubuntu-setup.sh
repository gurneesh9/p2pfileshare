sudo apt update & sudo apt install -y git vim build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/gurneesh9/p2pfileshare
cd p2pfileshare
cargo build -p xend-core
cargo build -p xend-cli

