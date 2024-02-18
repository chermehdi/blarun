#!/bin/bash

cargo build --release

sudo mv target/release/blarun /usr/local/bin/blarun
