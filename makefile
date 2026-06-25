install:
	cargo build --release --bin porto
	install -o root -g root -m 755 target/release/porto /usr/local/bin/
	bash scripts/install.sh
