#!/usr/bin/env bash
# Temporary round-8 cluster-6 validation runner (deleted before commit).
cd /home/hermes/projects/flycockpit/0006 || exit 1
FILTER='test(tools::shell_compress) | test(tools::task) | test(tools::skill_manage) | test(tools::mcp_tool) | test(mcp::sandbox) | test(mcp_host_gate) | test(drop_front_margin) | test(drop_back_margin) | test(tools::bash::tests::compression)'
CARGO_TARGET_DIR=target cargo nextest run --locked -p cockpit-core -E "$FILTER" > /tmp/cluster_r8c6.log 2>&1
echo "EXIT:$?" >> /tmp/cluster_r8c6.log
